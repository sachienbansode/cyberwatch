-- =====================================================================
--  VAPT module tables (schemas: identity, asset, vapt, audit)
--  Depends on 01_schemas.sql
-- =====================================================================
\connect cyberwatch

-- ---- identity (minimal, for FK integrity) ----
CREATE TABLE IF NOT EXISTS identity.tenants (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL,
  re_category   text NOT NULL DEFAULT 'Qualified',   -- MII | Qualified | Mid | Small | SelfCert
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- ---- asset ----
CREATE TABLE IF NOT EXISTS asset.assets (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES identity.tenants(id),
  name          text NOT NULL,
  type          text NOT NULL DEFAULT 'Web App',      -- Web App | API | Mobile | Network | Database
  base_url      text,
  criticality   text NOT NULL DEFAULT 'High',         -- Critical | High | Medium | Low
  environment   text NOT NULL DEFAULT 'Production',
  in_dmz        boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_assets_tenant ON asset.assets(tenant_id);

-- ---- vapt.scan_authorizations : the safety gate for active testing ----
CREATE TABLE IF NOT EXISTS vapt.scan_authorizations (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES identity.tenants(id),
  asset_id       uuid NOT NULL REFERENCES asset.assets(id),
  scope_hosts    text[] NOT NULL,        -- explicit in-scope hostnames permitted for active testing
  authorized_by  text NOT NULL,          -- name / role that granted authorisation
  authorization_ref text,                -- ticket / signed-form reference
  method         text NOT NULL DEFAULT 'active',   -- passive | baseline | active
  granted_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  active         boolean NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS ix_scanauth_asset ON vapt.scan_authorizations(asset_id);

-- ---- vapt.scanners : registry of available scanners ----
CREATE TABLE IF NOT EXISTS vapt.scanners (
  key       text PRIMARY KEY,            -- passive | zap-baseline | zap-active | nuclei | nmap | testssl
  name      text NOT NULL,
  kind      text NOT NULL,               -- passive | active
  tool      text,                        -- external binary, null for built-in
  enabled   boolean NOT NULL DEFAULT true
);

-- ---- vapt.scan_schedules : cadence engine ----
CREATE TABLE IF NOT EXISTS vapt.scan_schedules (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES identity.tenants(id),
  asset_id       uuid NOT NULL REFERENCES asset.assets(id),
  test_type      text NOT NULL,          -- VA | PT
  cadence_months int  NOT NULL,          -- RBI: VA=6, PT=12 for critical/DMZ
  next_run_at    timestamptz NOT NULL
);

-- ---- vapt.scan_jobs ----
CREATE TABLE IF NOT EXISTS vapt.scan_jobs (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES identity.tenants(id),
  asset_id       uuid NOT NULL REFERENCES asset.assets(id),
  authorization_id uuid REFERENCES vapt.scan_authorizations(id),
  profile        text NOT NULL DEFAULT 'passive',   -- passive | baseline | active
  target_url     text NOT NULL,
  scanners       text[] NOT NULL DEFAULT '{}',
  status         text NOT NULL DEFAULT 'queued',    -- queued | running | completed | failed | blocked
  status_reason  text,
  summary        jsonb NOT NULL DEFAULT '{}'::jsonb,
  queued_at      timestamptz NOT NULL DEFAULT now(),
  started_at     timestamptz,
  finished_at    timestamptz
);
CREATE INDEX IF NOT EXISTS ix_jobs_status ON vapt.scan_jobs(status);
CREATE INDEX IF NOT EXISTS ix_jobs_asset  ON vapt.scan_jobs(asset_id);

-- ---- vapt.findings ----
CREATE TABLE IF NOT EXISTS vapt.findings (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES identity.tenants(id),
  scan_job_id    uuid NOT NULL REFERENCES vapt.scan_jobs(id),
  asset_id       uuid NOT NULL REFERENCES asset.assets(id),
  fingerprint    text NOT NULL,          -- for de-duplication across scans
  title          text NOT NULL,
  description    text,
  remediation    text,
  severity       text NOT NULL,          -- Critical | High | Medium | Low | Info
  cvss           numeric(3,1),
  cwe            text,
  category       text,                   -- tls | headers | cookies | exposure | injection | network | dependency
  scanner        text,
  evidence       jsonb NOT NULL DEFAULT '{}'::jsonb,
  framework_refs text[] NOT NULL DEFAULT '{}',  -- e.g. {RBI:Sec 16, SEBI:PR.DS}
  status         text NOT NULL DEFAULT 'Open',  -- Open | In Progress | Closed | Accepted Risk
  due_at         timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_dedupe ON vapt.findings(asset_id, fingerprint);
CREATE INDEX IF NOT EXISTS ix_findings_job ON vapt.findings(scan_job_id);

-- ---- vapt.remediation_tasks ----
CREATE TABLE IF NOT EXISTS vapt.remediation_tasks (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id   uuid NOT NULL REFERENCES vapt.findings(id),
  owner        text,
  sla_due      timestamptz,
  state        text NOT NULL DEFAULT 'Open',
  notes        text,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

-- ---- audit.audit_log (append-only) ----
CREATE TABLE IF NOT EXISTS audit.audit_log (
  id         bigserial PRIMARY KEY,
  tenant_id  uuid,
  actor      text,
  action     text NOT NULL,
  entity     text,
  entity_id  text,
  detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
  ts         timestamptz NOT NULL DEFAULT now()
);
-- prevent updates/deletes on the audit trail
CREATE OR REPLACE RULE audit_no_update AS ON UPDATE TO audit.audit_log DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_no_delete AS ON DELETE TO audit.audit_log DO INSTEAD NOTHING;
