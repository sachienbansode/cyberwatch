import { query, audit } from './db';
import { runJob } from './engine';

let running = false;
export async function tick() {
  if (running) return;
  running = true;
  try {
    const [job] = await query<any>(
      `SELECT id FROM vapt.scan_jobs WHERE status='queued' ORDER BY queued_at ASC LIMIT 1`);
    if (job) {
      try { await runJob(job.id); }
      catch (e: any) {
        await query('UPDATE vapt.scan_jobs SET status=CASE WHEN status=$3 THEN status ELSE $2 END, status_reason=$4 WHERE id=$1',
          [job.id, 'failed', 'blocked', e.message]);
      }
    }
  } catch (e: any) { /* transient DB error — retry next tick */ }
  finally { running = false; }
}
export function startWorker(intervalMs = 3000) {
  console.log('[worker] polling vapt.scan_jobs every', intervalMs, 'ms');
  setInterval(tick, intervalMs);
}
if (require.main === module) startWorker();
