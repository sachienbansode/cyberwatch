-- =====================================================================
--  Vulnerability management: enriched findings, history, imports
--  Depends on 01/02/04
-- =====================================================================
\connect cyberwatch

ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS cve         text;
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS cvss_vector text;
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS refs        text[] NOT NULL DEFAULT '{}';
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS epss        numeric;
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS kev         boolean NOT NULL DEFAULT false;
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS risk_score  numeric;
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS owner       text;
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS source      text NOT NULL DEFAULT 'scanner';  -- scanner | import:<tool> | manual
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS first_seen  timestamptz NOT NULL DEFAULT now();
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS last_seen   timestamptz NOT NULL DEFAULT now();

-- finding lifecycle events (status changes, comments, imports, enrichment)
CREATE TABLE IF NOT EXISTS vapt.finding_events (
  id         bigserial PRIMARY KEY,
  tenant_id  uuid,
  finding_id uuid REFERENCES vapt.findings(id),
  actor      text,
  type       text NOT NULL,            -- created | status | owner | comment | import | enrich
  detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
  ts         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_fevents_finding ON vapt.finding_events(finding_id);

-- import batches
CREATE TABLE IF NOT EXISTS vapt.imports (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  asset_id       uuid REFERENCES asset.assets(id),
  source         text NOT NULL,        -- nessus | nmap | zap | burp | sarif
  filename       text,
  findings_count int NOT NULL DEFAULT 0,
  imported_by    text,
  created_at     timestamptz NOT NULL DEFAULT now()
);
