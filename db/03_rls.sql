-- =====================================================================
--  Optional: row-level security for tenant isolation.
--  The service sets  SET app.tenant_id = '<uuid>'  per connection.
--  Apply AFTER the service role exists; skip for a quick single-tenant trial.
-- =====================================================================
\connect cyberwatch
DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT unnest(ARRAY['asset.assets','vapt.scan_authorizations','vapt.scan_schedules',
                               'vapt.scan_jobs','vapt.findings']) LOOP
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %s
              USING (tenant_id = current_setting('app.tenant_id', true)::uuid)$p$, t);
  END LOOP;
END $$;
