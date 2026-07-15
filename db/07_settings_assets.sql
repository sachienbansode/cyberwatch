-- =====================================================================
--  Settings (SLA policy, org lock), richer assets, active-scan consent
-- =====================================================================
\connect cyberwatch

CREATE TABLE IF NOT EXISTS vapt.settings (
  key text PRIMARY KEY, value jsonb NOT NULL DEFAULT '{}'::jsonb, updated_at timestamptz NOT NULL DEFAULT now()
);
-- SLA policy: remediation days by asset criticality x finding severity
INSERT INTO vapt.settings(key,value) VALUES ('sla_policy', '{
  "Critical": {"Critical":3,"High":7,"Medium":14,"Low":30,"Info":90},
  "High":     {"Critical":7,"High":7,"Medium":30,"Low":60,"Info":120},
  "Medium":   {"Critical":7,"High":15,"Medium":45,"Low":90,"Info":180},
  "Low":      {"Critical":15,"High":30,"Medium":60,"Low":120,"Info":365}
}'::jsonb) ON CONFLICT (key) DO NOTHING;
INSERT INTO vapt.settings(key,value) VALUES ('active_scans_locked','false'::jsonb) ON CONFLICT (key) DO NOTHING;

-- richer asset metadata
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS description         text;
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS owner               text;
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS business_unit       text;
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS region              text;
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS data_classification text;
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS tags                text[] NOT NULL DEFAULT '{}';
ALTER TABLE asset.assets ADD COLUMN IF NOT EXISTS notes               text;

-- record legal acceptance on authorizations
ALTER TABLE vapt.scan_authorizations ADD COLUMN IF NOT EXISTS accepted_at timestamptz;
