/**
 * Quick single-target scan.
 *   npm run scan -- https://example.com --profile passive
 *   npm run scan -- https://example.com --profile active --authorize "R. Sharma, CISO"
 * Active/baseline profiles require ACTIVE_SCANS_ENABLED=true AND an authorization for the host.
 * --authorize records an authorization on the spot (an explicit human attestation of authorised testing).
 */
import { query, pool } from './db';
import { runJob } from './engine';
import { config } from './config';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const url = process.argv[2];
  if (!url || url.startsWith('--')) { console.error('usage: npm run scan -- <url> [--profile passive|baseline|active] [--authorize "name"]'); process.exit(1); }
  const profile = (arg('--profile') || 'passive') as any;
  const host = new URL(url).hostname;
  const tenant = config.defaultTenant;

  // find or create an asset for this URL
  let [asset] = await query<any>('SELECT * FROM asset.assets WHERE tenant_id=$1 AND base_url=$2', [tenant, url]);
  if (!asset) [asset] = await query<any>(
    `INSERT INTO asset.assets(tenant_id,name,base_url) VALUES ($1,$2,$3) RETURNING *`, [tenant, host, url]);

  const authorizeBy = arg('--authorize');
  if (authorizeBy) {
    await query(`INSERT INTO vapt.scan_authorizations(tenant_id,asset_id,scope_hosts,authorized_by,method,expires_at)
                 VALUES ($1,$2,$3,$4,$5, now() + interval '1 day')`, [tenant, asset.id, [host], authorizeBy, 'active']);
    console.log(`[cli] authorization recorded for ${host} by "${authorizeBy}"`);
  }

  const [job] = await query<any>(
    `INSERT INTO vapt.scan_jobs(tenant_id,asset_id,profile,target_url) VALUES ($1,$2,$3,$4) RETURNING *`,
    [tenant, asset.id, profile, url]);

  console.log(`[cli] scanning ${url} (profile: ${profile}) ...`);
  try {
    const summary = await runJob(job.id);
    const rows = await query<any>('SELECT severity,title,category,scanner FROM vapt.findings WHERE scan_job_id=$1 ORDER BY (CASE severity WHEN \'Critical\' THEN 0 WHEN \'High\' THEN 1 WHEN \'Medium\' THEN 2 WHEN \'Low\' THEN 3 ELSE 4 END)', [job.id]);
    console.log(`\n  Findings (${summary.total}) — ` + JSON.stringify(summary.bySeverity));
    for (const r of rows) console.log(`   [${r.severity.padEnd(8)}] ${r.title}  (${r.scanner})`);
  } catch (e: any) {
    console.error('[cli] scan blocked/failed:', e.message);
  } finally {
    await pool.end();
  }
}
main().catch(e => { console.error(e); process.exit(1); });
