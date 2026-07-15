import express, { Response } from 'express';
import * as path from 'path';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { query, audit } from './db';
import { config } from './config';
import { login, requireAuth, AuthedReq } from './auth';
import { streamReport } from './report';

export function createApp() {
  const app = express();
  app.use(express.json());
  // public: web UI + health
  app.use(express.static(path.join(__dirname, '..', 'public')));
  app.get('/health', (_req, res) => res.json({ ok: true, activeScansEnabled: config.activeScansEnabled }));

  // ---- Auth ----
  app.post('/api/v1/auth/login', async (req, res) => {
    const s = z.object({ email: z.string(), password: z.string() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: 'email and password required' });
    try { res.json(await login(s.data.email, s.data.password)); }
    catch { res.status(401).json({ error: 'invalid credentials' }); }
  });
  app.get('/api/v1/auth/me', requireAuth(), (req: AuthedReq, res) => res.json(req.user));

  // ---- Assets ----
  app.get('/api/v1/assets', requireAuth('asset:read'), async (req: AuthedReq, res) => {
    res.json(await query('SELECT * FROM asset.assets WHERE tenant_id=$1 ORDER BY created_at DESC', [req.user!.tenant]));
  });
  app.post('/api/v1/assets', requireAuth('asset:write'), async (req: AuthedReq, res) => {
    const s = z.object({ name: z.string(), baseUrl: z.string().url(), type: z.string().optional(),
      criticality: z.string().optional(), environment: z.string().optional(), inDmz: z.boolean().optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    const [row] = await query(`INSERT INTO asset.assets(tenant_id,name,base_url,type,criticality,environment,in_dmz)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.user!.tenant, b.name, b.baseUrl, b.type || 'Web App', b.criticality || 'High', b.environment || 'Production', b.inDmz ?? true]);
    await audit(req.user!.tenant, req.user!.email, 'asset.created', 'asset', (row as any).id, { name: b.name });
    res.status(201).json(row);
  });
  app.post('/api/v1/assets/:id/authorizations', requireAuth('scan:run'), async (req: AuthedReq, res) => {
    const s = z.object({ scopeHosts: z.array(z.string()).min(1), authorizedBy: z.string(),
      authorizationRef: z.string().optional(), method: z.enum(['passive','baseline','active']).optional(),
      expiresInDays: z.number().int().positive().max(365).optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    const [row] = await query(`INSERT INTO vapt.scan_authorizations(tenant_id,asset_id,scope_hosts,authorized_by,authorization_ref,method,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6, now() + ($7 || ' days')::interval) RETURNING *`,
      [req.user!.tenant, req.params.id, b.scopeHosts, b.authorizedBy, b.authorizationRef || null, b.method || 'active', String(b.expiresInDays || 30)]);
    await audit(req.user!.tenant, req.user!.email, 'authorization.granted', 'asset', req.params.id, { scopeHosts: b.scopeHosts });
    res.status(201).json(row);
  });

  // ---- Scan jobs ----
  app.post('/api/v1/scan-jobs', requireAuth('scan:run'), async (req: AuthedReq, res) => {
    const s = z.object({ assetId: z.string().uuid(), profile: z.enum(['passive','baseline','active']).default('passive'),
      targetUrl: z.string().url().optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    const [asset] = await query<any>('SELECT * FROM asset.assets WHERE id=$1 AND tenant_id=$2', [b.assetId, req.user!.tenant]);
    if (!asset) return res.status(404).json({ error: 'asset not found' });
    const target = b.targetUrl || asset.base_url;
    if (!target) return res.status(400).json({ error: 'no target_url and asset has no base_url' });
    const [{ v }] = await query<any>('SELECT coalesce(max(version),0)+1 AS v FROM vapt.scan_jobs WHERE asset_id=$1', [b.assetId]);
    const [job] = await query(`INSERT INTO vapt.scan_jobs(tenant_id,asset_id,profile,target_url,version,requested_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.user!.tenant, b.assetId, b.profile, target, v, req.user!.email]);
    await audit(req.user!.tenant, req.user!.email, 'scan.queued', 'scan_job', (job as any).id, { profile: b.profile, target, version: v });
    res.status(202).json(job);
  });
  app.get('/api/v1/scan-jobs', requireAuth('scan:read'), async (req: AuthedReq, res) => {
    const params: any[] = [req.user!.tenant]; let sql = 'SELECT * FROM vapt.scan_jobs WHERE tenant_id=$1';
    if (req.query.assetId) { params.push(req.query.assetId); sql += ` AND asset_id=$${params.length}`; }
    sql += ' ORDER BY queued_at DESC LIMIT 200';
    res.json(await query(sql, params));
  });
  app.get('/api/v1/scan-jobs/:id', requireAuth('scan:read'), async (req: AuthedReq, res) => {
    const [job] = await query('SELECT * FROM vapt.scan_jobs WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user!.tenant]);
    if (!job) return res.status(404).json({ error: 'not found' });
    res.json(job);
  });
  app.get('/api/v1/scan-jobs/:id/report.pdf', requireAuth('report:read'), async (req: AuthedReq, res: Response) => {
    await streamReport(req.params.id, req.user!.tenant, res);
  });

  // ---- Findings ----
  app.get('/api/v1/findings', requireAuth('finding:read'), async (req: AuthedReq, res) => {
    const params: any[] = [req.user!.tenant]; let sql = 'SELECT * FROM vapt.findings WHERE tenant_id=$1';
    for (const [q, col] of [['assetId','asset_id'],['scanJobId','scan_job_id'],['status','status']] as const) {
      if (req.query[q]) { params.push(req.query[q]); sql += ` AND ${col}=$${params.length}`; }
    }
    sql += " ORDER BY (CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END), created_at DESC LIMIT 500";
    res.json(await query(sql, params));
  });
  app.patch('/api/v1/findings/:id', requireAuth('finding:write'), async (req: AuthedReq, res) => {
    const s = z.object({ status: z.enum(['Open','In Progress','Closed','Accepted Risk']) }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const [row] = await query('UPDATE vapt.findings SET status=$3 WHERE id=$1 AND tenant_id=$2 RETURNING *', [req.params.id, req.user!.tenant, s.data.status]);
    if (!row) return res.status(404).json({ error: 'not found' });
    await audit(req.user!.tenant, req.user!.email, 'finding.updated', 'finding', req.params.id, { status: s.data.status });
    res.json(row);
  });

  // ---- Stats ----
  app.get('/api/v1/stats', requireAuth('asset:read'), async (req: AuthedReq, res) => {
    const t = req.user!.tenant;
    const [a] = await query('SELECT count(*)::int n FROM asset.assets WHERE tenant_id=$1', [t]);
    const sev = await query(`SELECT severity, count(*)::int n FROM vapt.findings WHERE tenant_id=$1 AND status <> 'Closed' GROUP BY severity`, [t]);
    const [jobs] = await query('SELECT count(*)::int n FROM vapt.scan_jobs WHERE tenant_id=$1', [t]);
    res.json({ assets: a?.n || 0, findingsBySeverity: sev, scanJobs: jobs?.n || 0 });
  });

  // ---- Users & roles (admin) ----
  app.get('/api/v1/roles', requireAuth('user:manage'), async (_req, res) => res.json(await query('SELECT id,name,description,permissions FROM identity.roles ORDER BY name')));
  app.get('/api/v1/users', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    res.json(await query(`SELECT u.id,u.email,u.name,u.status,u.last_login_at,r.name AS role
       FROM identity.users u JOIN identity.roles r ON r.id=u.role_id WHERE u.tenant_id=$1 ORDER BY u.created_at`, [req.user!.tenant]));
  });
  app.post('/api/v1/users', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    const s = z.object({ email: z.string().email(), name: z.string(), password: z.string().min(8), role: z.string() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    const [role] = await query<any>('SELECT id FROM identity.roles WHERE name=$1', [b.role]);
    if (!role) return res.status(400).json({ error: 'unknown role' });
    const hash = await bcrypt.hash(b.password, 10);
    try {
      const [row] = await query(`INSERT INTO identity.users(tenant_id,email,name,password_hash,role_id)
         VALUES ($1,$2,$3,$4,$5) RETURNING id,email,name,status`, [req.user!.tenant, b.email, b.name, hash, role.id]);
      await audit(req.user!.tenant, req.user!.email, 'user.created', 'user', (row as any).id, { email: b.email, role: b.role });
      res.status(201).json(row);
    } catch (e: any) { res.status(409).json({ error: 'email already exists' }); }
  });

  return app;
}
