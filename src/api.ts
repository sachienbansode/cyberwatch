import express from 'express';
import * as path from 'path';
import { z } from 'zod';
import { query, audit } from './db';
import { config } from './config';

export function createApp() {
  const app = express();
  app.use(express.json());
  // Serve the AntShield web UI (public/) at the site root
  app.use(express.static(path.join(__dirname, '..', 'public')));
  const tenant = config.defaultTenant;

  app.get('/health', (_req, res) => res.json({ ok: true, activeScansEnabled: config.activeScansEnabled }));

  // ---- Assets ----
  app.get('/api/v1/assets', async (_req, res) => {
    res.json(await query('SELECT * FROM asset.assets WHERE tenant_id=$1 ORDER BY created_at DESC', [tenant]));
  });
  app.post('/api/v1/assets', async (req, res) => {
    const s = z.object({ name: z.string(), baseUrl: z.string().url(), type: z.string().optional(),
      criticality: z.string().optional(), environment: z.string().optional(), inDmz: z.boolean().optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    const [row] = await query(
      `INSERT INTO asset.assets(tenant_id,name,base_url,type,criticality,environment,in_dmz)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [tenant, b.name, b.baseUrl, b.type || 'Web App', b.criticality || 'High', b.environment || 'Production', b.inDmz ?? true]);
    await audit(tenant, 'api', 'asset.created', 'asset', (row as any).id, { name: b.name });
    res.status(201).json(row);
  });

  // ---- Authorizations (required before active testing) ----
  app.post('/api/v1/assets/:id/authorizations', async (req, res) => {
    const s = z.object({ scopeHosts: z.array(z.string()).min(1), authorizedBy: z.string(),
      authorizationRef: z.string().optional(), method: z.enum(['passive', 'baseline', 'active']).optional(),
      expiresInDays: z.number().int().positive().max(365).optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    const [row] = await query(
      `INSERT INTO vapt.scan_authorizations(tenant_id,asset_id,scope_hosts,authorized_by,authorization_ref,method,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6, now() + ($7 || ' days')::interval) RETURNING *`,
      [tenant, req.params.id, b.scopeHosts, b.authorizedBy, b.authorizationRef || null, b.method || 'active', String(b.expiresInDays || 30)]);
    await audit(tenant, 'api', 'authorization.granted', 'asset', req.params.id, { scopeHosts: b.scopeHosts, by: b.authorizedBy });
    res.status(201).json(row);
  });

  // ---- Scan jobs ----
  app.post('/api/v1/scan-jobs', async (req, res) => {
    const s = z.object({ assetId: z.string().uuid(), profile: z.enum(['passive', 'baseline', 'active']).default('passive'),
      targetUrl: z.string().url().optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    const [asset] = await query<any>('SELECT * FROM asset.assets WHERE id=$1 AND tenant_id=$2', [b.assetId, tenant]);
    if (!asset) return res.status(404).json({ error: 'asset not found' });
    const target = b.targetUrl || asset.base_url;
    if (!target) return res.status(400).json({ error: 'no target_url and asset has no base_url' });
    const [job] = await query(
      `INSERT INTO vapt.scan_jobs(tenant_id,asset_id,profile,target_url) VALUES ($1,$2,$3,$4) RETURNING *`,
      [tenant, b.assetId, b.profile, target]);
    await audit(tenant, 'api', 'scan.queued', 'scan_job', (job as any).id, { profile: b.profile, target });
    res.status(202).json(job);
  });
  app.get('/api/v1/scan-jobs', async (_req, res) => {
    res.json(await query('SELECT * FROM vapt.scan_jobs WHERE tenant_id=$1 ORDER BY queued_at DESC LIMIT 100', [tenant]));
  });
  app.get('/api/v1/scan-jobs/:id', async (req, res) => {
    const [job] = await query('SELECT * FROM vapt.scan_jobs WHERE id=$1 AND tenant_id=$2', [req.params.id, tenant]);
    if (!job) return res.status(404).json({ error: 'not found' });
    res.json(job);
  });

  // ---- Findings ----
  app.get('/api/v1/findings', async (req, res) => {
    const params: any[] = [tenant]; let sql = 'SELECT * FROM vapt.findings WHERE tenant_id=$1';
    if (req.query.assetId) { params.push(req.query.assetId); sql += ` AND asset_id=$${params.length}`; }
    if (req.query.status) { params.push(req.query.status); sql += ` AND status=$${params.length}`; }
    sql += ' ORDER BY (CASE severity WHEN \'Critical\' THEN 0 WHEN \'High\' THEN 1 WHEN \'Medium\' THEN 2 WHEN \'Low\' THEN 3 ELSE 4 END), created_at DESC LIMIT 500';
    res.json(await query(sql, params));
  });

  // ---- Update a finding (remediation) ----
  app.patch('/api/v1/findings/:id', async (req, res) => {
    const s = z.object({ status: z.enum(['Open', 'In Progress', 'Closed', 'Accepted Risk']) }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const [row] = await query('UPDATE vapt.findings SET status=$3 WHERE id=$1 AND tenant_id=$2 RETURNING *', [req.params.id, tenant, s.data.status]);
    if (!row) return res.status(404).json({ error: 'not found' });
    await audit(tenant, 'api', 'finding.updated', 'finding', req.params.id, { status: s.data.status });
    res.json(row);
  });

  // ---- Dashboard stats (computed) ----
  app.get('/api/v1/stats', async (_req, res) => {
    const [a] = await query('SELECT count(*)::int n FROM asset.assets WHERE tenant_id=$1', [tenant]);
    const sev = await query(`SELECT severity, count(*)::int n FROM vapt.findings WHERE tenant_id=$1 AND status <> 'Closed' GROUP BY severity`, [tenant]);
    const [due] = await query(`SELECT count(*)::int n FROM vapt.findings WHERE tenant_id=$1 AND status <> 'Closed' AND due_at < now() + interval '7 days'`, [tenant]);
    const [jobs] = await query('SELECT count(*)::int n FROM vapt.scan_jobs WHERE tenant_id=$1', [tenant]);
    res.json({ assets: a?.n || 0, findingsBySeverity: sev, dueSoon: due?.n || 0, scanJobs: jobs?.n || 0 });
  });

  return app;
}
