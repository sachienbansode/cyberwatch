-- =====================================================================
--  Baseline risk backfill, screenshots, evidence, authenticated-scan config
--  Depends on 01/02/04/05
-- =====================================================================
\connect cyberwatch

-- Backfill a baseline risk score for findings that never got one
UPDATE vapt.findings SET risk_score = CASE severity
   WHEN 'Critical' THEN 92 WHEN 'High' THEN 75 WHEN 'Medium' THEN 55 WHEN 'Low' THEN 32 ELSE 14 END
 WHERE risk_score IS NULL;

-- Screenshots (base64 PNG) tied to asset / scan / finding
CREATE TABLE IF NOT EXISTS vapt.screenshots (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid,
  asset_id    uuid REFERENCES asset.assets(id),
  scan_job_id uuid,
  finding_id  uuid,
  kind        text NOT NULL DEFAULT 'asset',
  caption     text,
  image_b64   text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_shot_asset ON vapt.screenshots(asset_id);
CREATE INDEX IF NOT EXISTS ix_shot_finding ON vapt.screenshots(finding_id);

-- Authenticated-scan configuration per asset
CREATE TABLE IF NOT EXISTS asset.asset_auth (
  asset_id    uuid PRIMARY KEY REFERENCES asset.assets(id),
  method      text NOT NULL DEFAULT 'none',   -- none | form | bearer | cookie | header
  login_url   text,
  username    text,
  secret      text,                            -- password / token / cookie / header value
  extra       jsonb NOT NULL DEFAULT '{}'::jsonb,  -- {userField,passField,headerName}
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Extra target URLs (e.g. imported from an OpenAPI / Swagger spec)
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS extra_urls text[] NOT NULL DEFAULT '{}';
