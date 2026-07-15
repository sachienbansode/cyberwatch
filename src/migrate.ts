// Applies the SQL files in ../db in order. Run:  npm run migrate
import { readFileSync } from 'fs';
import { join } from 'path';
import { pool } from './db';

const files = ['01_schemas.sql', '02_vapt_tables.sql', 'seed.sql', '04_auth_progress.sql', '05_vulnmgmt.sql', '06_evidence_auth.sql', '07_settings_assets.sql', '08_impact.sql', '09_compliance.sql'];
// 03_rls.sql is intentionally NOT auto-applied — enable it explicitly when ready.

async function main() {
  for (const f of files) {
    const sql = readFileSync(join(__dirname, '..', 'db', f), 'utf8')
      .split('\n').filter(l => !l.trim().startsWith('\\connect')).join('\n'); // strip psql meta-commands
    process.stdout.write(`applying ${f} ... `);
    await pool.query(sql);
    console.log('ok');
  }
  await pool.end();
  console.log('migration complete');
}
main().catch(e => { console.error('migration failed:', e.message); process.exit(1); });
