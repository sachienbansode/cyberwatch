import { createHash } from 'crypto';
import { withTenant, audit, query } from './db';
import { scannersFor, requiresAuthorization } from './scanners/registry';
import { assertActiveAuthorized, AuthorizationError } from './authorization';
import { enrich, slaDays } from './mapping';
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
      const fs = await s.run({ jobId, tenantId: job.tenant_id, assetId: job.asset_id, targetUrl: target, host, profile });
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
  await withTenant(job.tenant_id, async (c) => {
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      const fp = fingerprint(host, f);
      const due = new Date(Date.now() + slaDays(f.severity) * 86400000);
      await c.query(
        `INSERT INTO vapt.findings
           (tenant_id,scan_job_id,asset_id,fingerprint,title,description,remediation,severity,cvss,cwe,category,scanner,evidence,framework_refs,due_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         ON CONFLICT (asset_id,fingerprint) DO UPDATE
           SET scan_job_id=EXCLUDED.scan_job_id, description=EXCLUDED.description, severity=EXCLUDED.severity`,
        [job.tenant_id, jobId, job.asset_id, fp, f.title, f.description || null, f.remediation || null,
         f.severity, f.cvss || null, f.cwe || null, f.category, f.scanner, f.evidence || {}, f.frameworkRefs || [], due]);
    }
  });
  steps[storeIdx].status = 'done'; steps[storeIdx].finishedAt = new Date().toISOString(); steps[storeIdx].findings = findings.length;

  const summary = { scanners: usedScanners, total: findings.length, bySeverity: counts };
  await query('UPDATE vapt.scan_jobs SET status=$2, summary=$3, scanners=$4, steps=$5, progress=100, current_step=NULL, finished_at=now() WHERE id=$1',
    [jobId, 'completed', summary, usedScanners, JSON.stringify(steps)]);
  await audit(job.tenant_id, 'scan-engine', 'scan.completed', 'scan_job', jobId, summary);
  return summary;
}
