-- =====================================================================
--  Auth + RBAC (identity) and scan progress/versioning (vapt)
--  Depends on 01_schemas.sql, 02_vapt_tables.sql
-- =====================================================================
\connect cyberwatch

-- ---- RBAC: roles & users ----
CREATE TABLE IF NOT EXISTS identity.roles (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text UNIQUE NOT NULL,
  description  text,
  permissions  text[] NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS identity.users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES identity.tenants(id),
  email         text UNIQUE NOT NULL,
  name          text,
  password_hash text NOT NULL,
  role_id       uuid REFERENCES identity.roles(id),
  status        text NOT NULL DEFAULT 'active',
  last_login_at timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_users_tenant ON identity.users(tenant_id);

-- ---- scan job: progress, steps, version, timing estimate ----
ALTER TABLE vapt.scan_jobs ADD COLUMN IF NOT EXISTS progress          int  NOT NULL DEFAULT 0;
ALTER TABLE vapt.scan_jobs ADD COLUMN IF NOT EXISTS current_step      text;
ALTER TABLE vapt.scan_jobs ADD COLUMN IF NOT EXISTS steps             jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE vapt.scan_jobs ADD COLUMN IF NOT EXISTS version           int  NOT NULL DEFAULT 1;
ALTER TABLE vapt.scan_jobs ADD COLUMN IF NOT EXISTS estimated_seconds int;
ALTER TABLE vapt.scan_jobs ADD COLUMN IF NOT EXISTS requested_by      text;

-- ---- seed roles ----
INSERT INTO identity.roles(name,description,permissions) VALUES
 ('admin',  'Full administrative access', ARRAY['asset:read','asset:write','scan:read','scan:run','finding:read','finding:write','report:read','user:manage']),
 ('analyst','Run scans and remediate',    ARRAY['asset:read','asset:write','scan:read','scan:run','finding:read','finding:write','report:read']),
 ('auditor','Read access and reports',    ARRAY['asset:read','scan:read','finding:read','report:read']),
 ('viewer', 'Read-only',                  ARRAY['asset:read','scan:read','finding:read'])
ON CONFLICT (name) DO NOTHING;

-- ---- seed initial admin user (CHANGE THIS PASSWORD after first login) ----
INSERT INTO identity.users(tenant_id,email,name,password_hash,role_id)
SELECT '00000000-0000-0000-0000-000000000001','admin@treeants.tech','Administrator',
       crypt('ChangeMe#2026', gen_salt('bf')), r.id
FROM identity.roles r WHERE r.name='admin'
ON CONFLICT (email) DO NOTHING;
