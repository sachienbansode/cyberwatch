import * as dotenv from 'dotenv';
dotenv.config();

const bool = (v: string | undefined, d = false) =>
  v == null ? d : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());

export const config = {
  pg: {
    host: process.env.PGHOST || 'localhost',
    port: Number(process.env.PGPORT || 5432),
    database: process.env.PGDATABASE || 'cyberwatch',
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD || '',
    ssl: bool(process.env.PGSSL) ? { rejectUnauthorized: false } : undefined,
  },
  port: Number(process.env.PORT || 8080),
  defaultTenant: process.env.DEFAULT_TENANT || '00000000-0000-0000-0000-000000000001',
  logLevel: process.env.LOG_LEVEL || 'info',
  // SAFETY kill-switch: active/intrusive scanning is off unless explicitly enabled.
  activeScansEnabled: bool(process.env.ACTIVE_SCANS_ENABLED, false),
  tools: {
    zapBaseline: process.env.ZAP_BASELINE || 'zap-baseline.py',
    zapFull: process.env.ZAP_FULL || 'zap-full-scan.py',
    nuclei: process.env.NUCLEI_BIN || 'nuclei',
    nmap: process.env.NMAP_BIN || 'nmap',
    testssl: process.env.TESTSSL_BIN || 'testssl.sh',
  },
};
