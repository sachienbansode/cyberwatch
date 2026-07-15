# AntShield — VAPT Module (cyberwatch)

End-to-end Vulnerability Assessment & Penetration-Testing service for the AntShield platform:
Node.js/TypeScript **API + worker + PostgreSQL**, with a safe built-in passive analyser and an
orchestration layer for industry-standard active tools (OWASP ZAP, Nuclei, Nmap, testssl.sh).

> ⚠️ **Authorised testing only.** Active/intrusive scanning sends attack-style traffic. It is
> disabled by default (`ACTIVE_SCANS_ENABLED=false`) and, even when enabled, requires a stored,
> in-scope **authorization** record per target. Only scan systems your organisation owns or is
> contractually authorised to test.

## 1. Prerequisites
- Node.js 20+
- PostgreSQL database `cyberwatch` (the one on your EC2 host)
- (optional) Docker, for the ZAP/Nuclei containers — see `docker-compose.yml`

## 2. Configure
```bash
cp .env.example .env      # then edit DB credentials for cyberwatch
```

## 3. Create the database schemas
The layout uses one schema per module plus shared schemas (see `db/01_schemas.sql`).
```bash
# either apply via the migrate script (uses your .env):
npm install
npm run migrate
# ...or with psql directly:
psql -h $PGHOST -U $PGUSER -d cyberwatch -f db/01_schemas.sql
psql -h $PGHOST -U $PGUSER -d cyberwatch -f db/02_vapt_tables.sql
psql -h $PGHOST -U $PGUSER -d cyberwatch -f db/seed.sql
# optional, once a service role exists — tenant row-level security:
psql -h $PGHOST -U $PGUSER -d cyberwatch -f db/03_rls.sql
```

## 4. Run a passive scan on your own website (safe, no attack traffic)
```bash
npm run scan -- https://your-website.example --profile passive
```
This checks TLS/HTTPS enforcement, security headers (HSTS/CSP/…), cookie flags, TLS
protocol/cert, banner disclosure and `security.txt`, then stores normalised, CVSS-graded,
RBI/SEBI-mapped findings in `vapt.findings`.

## 5. Run the service (API + background worker)
```bash
npm run api        # http://localhost:8080
```
Key endpoints:
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/assets` | Register an asset (`name`, `baseUrl`, …) |
| POST | `/api/v1/assets/:id/authorizations` | Record authorisation + in-scope hosts (required for active) |
| POST | `/api/v1/scan-jobs` | Queue a scan (`assetId`, `profile`) |
| GET  | `/api/v1/scan-jobs/:id` | Job status + summary |
| GET  | `/api/v1/findings?assetId=` | Findings, severity-ordered |

## 6. Enabling active testing (only for authorised targets)
```bash
# 1) in .env
ACTIVE_SCANS_ENABLED=true
# 2) record an authorization (API), then:
npm run scan -- https://your-website.example --profile active --authorize "Name, Role"
```
Active profiles run Nuclei, Nmap, ZAP full scan and testssl.sh **if present on PATH / via Docker**;
missing tools are skipped gracefully. No exploit code ships here — the service only orchestrates
these established tools and normalises their output.

## Profiles
- **passive** — built-in, non-intrusive (default; runs anywhere).
- **baseline** — passive + ZAP baseline (spider/passive rules) + testssl. Requires authorization.
- **active** — full active suite. Requires `ACTIVE_SCANS_ENABLED=true` + authorization.

## Layout
```
db/        SQL — schemas (01), VAPT tables (02), optional RLS (03), seed
src/
  api.ts        REST API            engine.ts      scan orchestration + safety gate
  worker.ts     job poller          authorization.ts  active-scan gate
  scanners/     passive + active adapters
  migrate.ts    schema migrator     cli.ts         one-shot scanner
```
Aligned to the AntShield Technical Architecture (Deliverable 2); can evolve to NestJS + BullMQ.

## Create the first admin user
No default user is seeded. After running migrations, create your first admin in the DB (psql/pgAdmin):
```sql
INSERT INTO identity.users (tenant_id, email, name, password_hash, role_id)
SELECT '00000000-0000-0000-0000-000000000001','admin@yourorg.com','Administrator',
       crypt('ChangeMe#Strong1', gen_salt('bf')), r.id
FROM identity.roles r WHERE r.name='admin'
ON CONFLICT (email) DO NOTHING;
```
Then sign in and change the password / add more users from the Users screen.
