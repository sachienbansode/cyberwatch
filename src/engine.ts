import { createHash } from 'crypto';
import { withTenant, audit, query } from './db';
import { scannersFor, requiresAuthorization } from './scanners/registry';
import { assertActiveAuthorized, AuthorizationError } from './authorization';
import { enrich } from './mapping';
import { getSetting, DEFAULT_SLA, slaDaysFor } from './settings';
import { riskScore } from './enrich';
import { captureScreenshot, captureMany } from './screenshot';
import { Finding, Profile, Scanner } from './types';

function hostOf(url: string): string { try { return new URL(url).hostname; } catch { return url; } }
function fingerprint(host: string, f: Finding): string {
  return createHash('sha1').update(`${f.scanner}|${f.category}|${f.title}|${host}`).digest('hex');
}
// rough per-scanner time estimates (seconds) for the ETA
const EST: Record<string, number> = { passive: 8, 'zap-baseline': 120, 'zap-active': 300, nuclei: 120, nmap: 60, testssl: 90 };
const NAMES: Record<string, string> = { passive: 'Passive analysis (TLS, headers, cookies)', 'zap-baseline': 'OWASP ZAP baseline', 'zap-active': 'OWASP ZAP active scan', nuclei: 'Nuclei templates', nmap: 'Nmap service discovery', testssl: 'TLS deep audit (testssl.sh)' };

async function saveSteps(jobId: string, steps: any[], progress: number, current: string | null) {
  await query('UPDATE vapt.scan_jobs SET steps=$2, progress=$3, current_step=$4 WHERE id=$1', [jobId, JSON.stringify(steps), progress, current]);
}

export async function runJob(jobId: string) {
  const [job] = await query<any>('SELECT * FROM vapt.scan_jobs WHERE id=$1', [jobId]);
  if (!job) throw new Error('job not found');
  const [asset] = await query<any>('SELECT * FROM asset.assets WHERE id=$1', [job.asset_id]);
  const target = job.target_url;
  const host = hostOf(target);
  const profile: Profile = job.profile;
  const scanners: Scanner[] = scannersFor(profile);
  const [authCfg] = await query<any>('SELECT method, login_url AS "loginUrl", username, secret, extra FROM asset.asset_auth WHERE asset_id=$1', [job.asset_id]);
  const extraUrls: string[] = asset && asset.extra_urls ? asset.extra_urls : [];

  // build step plan (+ a final normalise step)
  const steps = scanners.map(s => ({ key: s.key, name: NAMES[s.key] || s.key, status: 'pending', startedAt: null, finishedAt: null, findings: 0 }));
  steps.push({ key: 'store', name: 'Normalise, score & store findings', status: 'pending', startedAt: null, finishedAt: null, findings: 0 });
  const estimate = scanners.reduce((a, s) => a + (EST[s.key] || 30), 4);
  const totalSteps = steps.length;

  await query('UPDATE vapt.scan_jobs SET status=$2, started_at=now(), estimated_seconds=$3, steps=$4, progress=1 WHERE id=$1',
    [jobId, 'running', estimate, JSON.stringify(steps)]);
  await audit(job.tenant_id, job.requested_by || 'scan-engine', 'scan.started', 'scan_job', jobId, { profile, target, version: job.version });

  // ---- SAFETY GATE ----
  try {
    if (requiresAuthorization(scanners)) await assertActiveAuthorized(job.asset_id, host);
    else {
      const assetHost = asset && asset.base_url ? hostOf(asset.base_url) : host;
      if (assetHost && assetHost !== host) throw new AuthorizationError(`Passive target host "${host}" does not match asset host "${assetHost}".`);
    }
  } catch (e: any) {
    await query('UPDATE vapt.scan_jobs SET status=$2, status_reason=$3, finished_at=now(), progress=0 WHERE id=$1', [jobId, 'blocked', e.message]);
    await audit(job.tenant_id, 'scan-engine', 'scan.blocked', 'scan_job', jobId, { reason: e.message });
    throw e;
  }

  // ---- Run scanners step by step ----
  const findings: Finding[] = [];
  const usedScanners: string[] = [];
  for (let i = 0; i < scanners.length; i++) {
    const s = scanners[i];
    steps[i].status = 'running'; steps[i].startedAt = new Date().toISOString();
    await saveSteps(jobId, steps, Math.round((i / totalSteps) * 100), steps[i].name);
    try {
      if (!(await s.available())) { steps[i].status = 'skipped'; steps[i].finishedAt = new Date().toISOString(); continue; }
      usedScanners.push(s.key);
      const fs = await s.run({ jobId, tenantId: job.tenant_id, assetId: job.asset_id, targetUrl: target, host, profile, auth: authCfg || { method: 'none' }, extraUrls });
      for (const f of fs) findings.push(enrich(f));
      steps[i].findings = fs.length;
      steps[i].status = 'done'; steps[i].finishedAt = new Date().toISOString();
    } catch (e: any) {
      steps[i].status = 'skipped'; steps[i].finishedAt = new Date().toISOString();
      await audit(job.tenant_id, 'scan-engine', 'scanner.error', 'scan_job', jobId, { scanner: s.key, error: e.message });
    }
    await saveSteps(jobId, steps, Math.round(((i + 1) / totalSteps) * 100), null);
  }

  // ---- Persist (dedupe + SLA) ----
  const storeIdx = steps.length - 1;
  steps[storeIdx].status = 'running'; steps[storeIdx].startedAt = new Date().toISOString();
  await saveSteps(jobId, steps, Math.round((storeIdx / totalSteps) * 100), steps[storeIdx].name);
  const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const slaPolicy = await getSetting('sla_policy', DEFAULT_SLA);
  await withTenant(job.tenant_id, async (c) => {
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      const fp = fingerprint(host, f);
      const due = new Date(Date.now() + slaDaysFor(slaPolicy, f.severity, asset ? asset.criticality : 'High') * 86400000);
      const risk = riskScore({ cvss: f.cvss, severity: f.severity, epss: null, kev: false, assetCriticality: asset ? asset.criticality : 'High' });
      await c.query(
        `INSERT INTO vapt.findings
           (tenant_id,scan_job_id,asset_id,fingerprint,title,description,remediation,severity,cvss,cwe,category,scanner,evidence,framework_refs,due_at,risk_score)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         ON CONFLICT (asset_id,fingerprint) DO UPDATE
           SET scan_job_id=EXCLUDED.scan_job_id, description=EXCLUDED.description, severity=EXCLUDED.severity, risk_score=EXCLUDED.risk_score, last_seen=now()`,
        [job.tenant_id, jobId, job.asset_id, fp, f.title, f.description || null, f.remediation || null,
         f.severity, f.cvss || null, f.cwe || null, f.category, f.scanner, f.evidence || {}, f.frameworkRefs || [], due, risk]);
    }
  });
  steps[storeIdx].status = 'done'; steps[storeIdx].finishedAt = new Date().toISOString(); steps[storeIdx].findings = findings.length;

  // capture screenshots: the target plus any URL-specific finding (evidence-justifying)
  try {
    const rows = await query<any>('SELECT id, evidence FROM vapt.findings WHERE scan_job_id=$1', [jobId]);
    const urlMap: Record<string, string> = { [target]: '' };
    for (const r of rows) { const u = r.evidence && r.evidence.url; if (u && !urlMap[u]) urlMap[u] = r.id; }
    const shots = await captureMany(Object.keys(urlMap));
    for (const [u, b64] of Object.entries(shots)) {
      const isTarget = u === target;
      await query('INSERT INTO vapt.screenshots(tenant_id,asset_id,scan_job_id,finding_id,kind,caption,image_b64) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [job.tenant_id, job.asset_id, jobId, isTarget ? null : (urlMap[u] || null), isTarget ? 'asset' : 'finding', u, b64]);
    }
  } catch { /* screenshots best-effort */ }

  const summary = { scanners: usedScanners, total: findings.length, bySeverity: counts };
  await query('UPDATE vapt.scan_jobs SET status=$2, summary=$3, scanners=$4, steps=$5, progress=100, current_step=NULL, finished_at=now() WHERE id=$1',
    [jobId, 'completed', summary, usedScanners, JSON.stringify(steps)]);
  await audit(job.tenant_id, 'scan-engine', 'scan.completed', 'scan_job', jobId, summary);
  return summary;
}
