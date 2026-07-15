import { createHash } from 'crypto';
import { withTenant, audit, query } from './db';
import { scannersFor, requiresAuthorization } from './scanners/registry';
import { assertActiveAuthorized, AuthorizationError } from './authorization';
import { enrich, slaDays } from './mapping';
import { Finding, Profile } from './types';

function hostOf(url: string): string { try { return new URL(url).hostname; } catch { return url; } }
function fingerprint(assetHost: string, f: Finding): string {
  return createHash('sha1').update(`${f.scanner}|${f.category}|${f.title}|${assetHost}`).digest('hex');
}

export async function runJob(jobId: string) {
  const [job] = await query<any>('SELECT * FROM vapt.scan_jobs WHERE id=$1', [jobId]);
  if (!job) throw new Error('job not found');
  const [asset] = await query<any>('SELECT * FROM asset.assets WHERE id=$1', [job.asset_id]);
  const target = job.target_url;
  const host = hostOf(target);
  const profile: Profile = job.profile;
  const scanners = scannersFor(profile);

  await query('UPDATE vapt.scan_jobs SET status=$2, started_at=now() WHERE id=$1', [jobId, 'running']);
  await audit(job.tenant_id, 'scan-engine', 'scan.started', 'scan_job', jobId, { profile, target });

  // ---- SAFETY GATE ----
  try {
    if (requiresAuthorization(scanners)) {
      await assertActiveAuthorized(job.asset_id, host);
    } else {
      // passive: only permit the asset's own host
      const assetHost = asset && asset.base_url ? hostOf(asset.base_url) : host;
      if (assetHost && assetHost !== host) {
        throw new AuthorizationError(`Passive target host "${host}" does not match the asset host "${assetHost}".`);
      }
    }
  } catch (e: any) {
    await query('UPDATE vapt.scan_jobs SET status=$2, status_reason=$3, finished_at=now() WHERE id=$1', [jobId, 'blocked', e.message]);
    await audit(job.tenant_id, 'scan-engine', 'scan.blocked', 'scan_job', jobId, { reason: e.message });
    throw e;
  }

  // ---- Run scanners ----
  const findings: Finding[] = [];
  const usedScanners: string[] = [];
  for (const s of scanners) {
    try {
      if (!(await s.available())) continue;
      usedScanners.push(s.key);
      const fs = await s.run({ jobId, tenantId: job.tenant_id, assetId: job.asset_id, targetUrl: target, host, profile });
      for (const f of fs) findings.push(enrich(f));
    } catch (e: any) {
      await audit(job.tenant_id, 'scan-engine', 'scanner.error', 'scan_job', jobId, { scanner: s.key, error: e.message });
    }
  }

  // ---- Persist (dedupe + SLA) ----
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
         f.severity, f.cvss || null, f.cwe || null, f.category, f.scanner, f.evidence || {}, f.frameworkRefs || [], due]
      );
    }
  });

  const summary = { scanners: usedScanners, total: findings.length, bySeverity: counts };
  await query('UPDATE vapt.scan_jobs SET status=$2, summary=$3, scanners=$4, finished_at=now() WHERE id=$1',
    [jobId, 'completed', summary, usedScanners]);
  await audit(job.tenant_id, 'scan-engine', 'scan.completed', 'scan_job', jobId, summary);
  return summary;
}
