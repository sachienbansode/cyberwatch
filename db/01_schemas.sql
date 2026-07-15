-- =====================================================================
--  cyberwatch — schema layout for the AntShield platform
--  Run once against the 'cyberwatch' database.
--  One schema per bounded context (module), plus shared/cross-cutting.
--  Convention: snake_case; every tenant-scoped table carries tenant_id.
-- =====================================================================
\connect cyberwatch

-- ---- Domain schemas (one per module) ----
CREATE SCHEMA IF NOT EXISTS identity;   COMMENT ON SCHEMA identity  IS 'Tenants, users, roles, RBAC, SSO, API keys';
CREATE SCHEMA IF NOT EXISTS asset;      COMMENT ON SCHEMA asset     IS 'M1 - Asset inventory, groups, criticality, DMZ tagging';
CREATE SCHEMA IF NOT EXISTS vapt;       COMMENT ON SCHEMA vapt      IS 'M1 - VAPT: scan schedules, jobs, findings, remediation, authorizations';
CREATE SCHEMA IF NOT EXISTS appsec;     COMMENT ON SCHEMA appsec    IS 'M2 - Application security: SAST/DAST/SCA, SBOM, escrow';
CREATE SCHEMA IF NOT EXISTS soc;        COMMENT ON SCHEMA soc       IS 'M3 - Security operations: detections, incidents, forensics';
CREATE SCHEMA IF NOT EXISTS vendor;     COMMENT ON SCHEMA vendor    IS 'M5 - Third-party / vendor risk';
CREATE SCHEMA IF NOT EXISTS rulelib;    COMMENT ON SCHEMA rulelib   IS 'M7 - Living rule library: regulatory clauses & control mappings';
CREATE SCHEMA IF NOT EXISTS grc;        COMMENT ON SCHEMA grc       IS 'M4 - Governance, risk & compliance: CCI, compliance status, policies';
CREATE SCHEMA IF NOT EXISTS reporting;  COMMENT ON SCHEMA reporting IS 'M6 - Reports & immutable evidence vault';

-- ---- Cross-cutting / shared schemas ----
CREATE SCHEMA IF NOT EXISTS audit;      COMMENT ON SCHEMA audit     IS 'Append-only audit trail (immutable)';
CREATE SCHEMA IF NOT EXISTS platform;   COMMENT ON SCHEMA platform  IS 'Tenant config, notifications, webhooks, scheduler state';
CREATE SCHEMA IF NOT EXISTS reference;  COMMENT ON SCHEMA reference IS 'Shared lookups: RE categories, frameworks, severities, cadence rules';
CREATE SCHEMA IF NOT EXISTS staging;    COMMENT ON SCHEMA staging   IS 'Raw scanner-ingestion staging before normalisation';

-- Useful extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
