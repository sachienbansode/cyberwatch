import express, { Response } from 'express';
import * as path from 'path';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { query, audit } from './db';
import { config } from './config';
import { login, requireAuth, AuthedReq } from './auth';
import { streamReport } from './report';
import { detectFormat, parseImport, parseOpenApiUrls } from './importers';
import { enrichFinding } from './enrich';
import { enrich as mapRefs, slaDays } from './mapping';
import { riskScore } from './enrich';
import { captureScreenshot } from './screenshot';
import { createHash } from 'crypto';

export function createApp() {
  const app = express();
  app.use(express.json({ limit: '30mb' }));
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
    const s = z.object({ status: z.enum(['Open','Confirmed','In Progress','False Positive','Accepted Risk','Fixed','Retest','Closed']).optional(),
      owner: z.string().optional(), severity: z.enum(['Critical','High','Medium','Low','Info']).optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const [cur] = await query<any>('SELECT * FROM vapt.findings WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user!.tenant]);
    if (!cur) return res.status(404).json({ error: 'not found' });
    const b = s.data;
    const [row] = await query('UPDATE vapt.findings SET status=coalesce($3,status), owner=coalesce($4,owner), severity=coalesce($5,severity) WHERE id=$1 AND tenant_id=$2 RETURNING *',
      [req.params.id, req.user!.tenant, b.status || null, b.owner || null, b.severity || null]);
    const ev = (type: string, detail: any) => query('INSERT INTO vapt.finding_events(tenant_id,finding_id,actor,type,detail) VALUES ($1,$2,$3,$4,$5)', [req.user!.tenant, req.params.id, req.user!.email, type, detail]);
    if (b.status && b.status !== cur.status) await ev('status', { from: cur.status, to: b.status });
    if (b.owner) await ev('owner', { owner: b.owner });
    await audit(req.user!.tenant, req.user!.email, 'finding.updated', 'finding', req.params.id, b);
    res.json(row);
  });


  // ---- Scanner import (Nessus / Nmap / ZAP / Burp / SARIF) ----
  app.post('/api/v1/assets/:id/imports', requireAuth('finding:write'), async (req: AuthedReq, res) => {
    const s = z.object({ format: z.enum(['nessus','nmap','zap','burp','sarif']).optional(), filename: z.string().optional(), content: z.string().min(1) }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const [asset] = await query<any>('SELECT * FROM asset.assets WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user!.tenant]);
    if (!asset) return res.status(404).json({ error: 'asset not found' });
    const fmt = s.data.format || detectFormat(s.data.content);
    if (!fmt) return res.status(400).json({ error: 'could not auto-detect format; please specify one' });
    let findings; try { findings = parseImport(fmt, s.data.content); } catch (e: any) { return res.status(400).json({ error: 'parse failed: ' + e.message }); }
    const host = (() => { try { return new URL(asset.base_url).hostname; } catch { return asset.name; } })();
    const [imp] = await query<any>('INSERT INTO vapt.imports(tenant_id,asset_id,source,filename,findings_count,imported_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [req.user!.tenant, asset.id, fmt, s.data.filename || null, findings.length, req.user!.email]);
    const counts: any = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    for (const f of findings) {
      mapRefs(f); counts[f.severity] = (counts[f.severity] || 0) + 1;
      const fp = createHash('sha1').update(`${f.scanner}|${f.category}|${f.title}|${host}`).digest('hex');
      const due = new Date(Date.now() + slaDays(f.severity) * 86400000);
      const risk = riskScore({ cvss: f.cvss, severity: f.severity, epss: null, kev: false, assetCriticality: asset.criticality });
      await query(`INSERT INTO vapt.findings (tenant_id,scan_job_id,asset_id,fingerprint,title,description,remediation,severity,cvss,cwe,category,scanner,evidence,framework_refs,due_at,cve,cvss_vector,refs,source,risk_score)
        VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        ON CONFLICT (asset_id,fingerprint) DO UPDATE SET last_seen=now(), severity=EXCLUDED.severity, description=EXCLUDED.description, risk_score=EXCLUDED.risk_score`,
        [req.user!.tenant, asset.id, fp, f.title, f.description || null, f.remediation || null, f.severity, f.cvss || null, f.cwe || null, f.category, f.scanner, f.evidence || {}, f.frameworkRefs || [], due, f.cve || null, f.cvssVector || null, f.refs || [], f.source || ('import:' + fmt), risk]);
    }
    await audit(req.user!.tenant, req.user!.email, 'findings.imported', 'import', imp.id, { source: fmt, count: findings.length });
    res.status(201).json({ importId: imp.id, source: fmt, imported: findings.length, bySeverity: counts });
  });
  app.get('/api/v1/imports', requireAuth('finding:read'), async (req: AuthedReq, res) => {
    const p: any[] = [req.user!.tenant]; let sql = 'SELECT * FROM vapt.imports WHERE tenant_id=$1';
    if (req.query.assetId) { p.push(req.query.assetId); sql += ` AND asset_id=$${p.length}`; }
    sql += ' ORDER BY created_at DESC LIMIT 100'; res.json(await query(sql, p));
  });

  // ---- Finding detail, history, comments, enrichment ----
  app.get('/api/v1/findings/:id', requireAuth('finding:read'), async (req: AuthedReq, res) => {
    const [f] = await query('SELECT * FROM vapt.findings WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user!.tenant]);
    if (!f) return res.status(404).json({ error: 'not found' }); res.json(f);
  });
  app.get('/api/v1/findings/:id/events', requireAuth('finding:read'), async (req: AuthedReq, res) => {
    res.json(await query('SELECT * FROM vapt.finding_events WHERE finding_id=$1 ORDER BY ts', [req.params.id]));
  });
  app.post('/api/v1/findings/:id/events', requireAuth('finding:write'), async (req: AuthedReq, res) => {
    const s = z.object({ comment: z.string().min(1) }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: 'comment required' });
    await query('INSERT INTO vapt.finding_events(tenant_id,finding_id,actor,type,detail) VALUES ($1,$2,$3,$4,$5)', [req.user!.tenant, req.params.id, req.user!.email, 'comment', { comment: s.data.comment }]);
    res.status(201).json({ ok: true });
  });
  app.post('/api/v1/findings/:id/enrich', requireAuth('finding:write'), async (req: AuthedReq, res) => {
    const [f] = await query<any>('SELECT f.*, a.criticality FROM vapt.findings f JOIN asset.assets a ON a.id=f.asset_id WHERE f.id=$1 AND f.tenant_id=$2', [req.params.id, req.user!.tenant]);
    if (!f) return res.status(404).json({ error: 'not found' });
    const en = await enrichFinding({ cve: f.cve, cvss: f.cvss ? Number(f.cvss) : undefined, severity: f.severity }, f.criticality);
    const [row] = await query('UPDATE vapt.findings SET epss=$3, kev=$4, risk_score=$5 WHERE id=$1 AND tenant_id=$2 RETURNING *', [req.params.id, req.user!.tenant, en.epss, en.kev, en.risk_score]);
    await query('INSERT INTO vapt.finding_events(tenant_id,finding_id,actor,type,detail) VALUES ($1,$2,$3,$4,$5)', [req.user!.tenant, req.params.id, req.user!.email, 'enrich', en]);
    res.json(row);
  });


  // ---- Screenshots ----
  const sendShot = async (row: any, res: Response) => {
    if (!row || !row.image_b64) return res.status(404).json({ error: 'no screenshot' });
    res.setHeader('Content-Type', 'image/png');
    res.end(Buffer.from(row.image_b64, 'base64'));
  };
  app.get('/api/v1/scan-jobs/:id/screenshot', requireAuth('scan:read'), async (req: AuthedReq, res) => {
    const [row] = await query<any>('SELECT image_b64 FROM vapt.screenshots WHERE scan_job_id=$1 AND tenant_id=$2 ORDER BY created_at DESC LIMIT 1', [req.params.id, req.user!.tenant]);
    await sendShot(row, res);
  });
  app.get('/api/v1/assets/:id/screenshot', requireAuth('asset:read'), async (req: AuthedReq, res) => {
    const [row] = await query<any>('SELECT image_b64 FROM vapt.screenshots WHERE asset_id=$1 AND tenant_id=$2 ORDER BY created_at DESC LIMIT 1', [req.params.id, req.user!.tenant]);
    await sendShot(row, res);
  });
  app.get('/api/v1/scan-jobs/:id/has-screenshot', requireAuth('scan:read'), async (req: AuthedReq, res) => {
    const [row] = await query<any>('SELECT id FROM vapt.screenshots WHERE scan_job_id=$1 AND tenant_id=$2 LIMIT 1', [req.params.id, req.user!.tenant]);
    res.json({ has: !!row });
  });

  // ---- Authenticated-scan config ----
  app.get('/api/v1/assets/:id/auth', requireAuth('scan:run'), async (req: AuthedReq, res) => {
    const [row] = await query<any>('SELECT asset_id, method, login_url, username, extra, (secret IS NOT NULL AND secret <> \'\') AS has_secret FROM asset.asset_auth WHERE asset_id=$1', [req.params.id]);
    res.json(row || { method: 'none' });
  });
  app.put('/api/v1/assets/:id/auth', requireAuth('scan:run'), async (req: AuthedReq, res) => {
    const s = z.object({ method: z.enum(['none','form','bearer','cookie','header']), loginUrl: z.string().optional(), username: z.string().optional(), secret: z.string().optional(), extra: z.record(z.any()).optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    await query(`INSERT INTO asset.asset_auth(asset_id,method,login_url,username,secret,extra,updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,now())
       ON CONFLICT (asset_id) DO UPDATE SET method=EXCLUDED.method, login_url=EXCLUDED.login_url, username=EXCLUDED.username,
         secret=COALESCE(NULLIF(EXCLUDED.secret,''), asset.asset_auth.secret), extra=EXCLUDED.extra, updated_at=now()`,
      [req.params.id, b.method, b.loginUrl || null, b.username || null, b.secret || '', b.extra || {}]);
    await audit(req.user!.tenant, req.user!.email, 'asset.auth_configured', 'asset', req.params.id, { method: b.method });
    res.json({ ok: true });
  });

  // ---- OpenAPI import (expands the scan surface) ----
  app.post('/api/v1/assets/:id/openapi', requireAuth('asset:write'), async (req: AuthedReq, res) => {
    const s = z.object({ content: z.string().min(2) }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: 'content required' });
    const [asset] = await query<any>('SELECT * FROM asset.assets WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user!.tenant]);
    if (!asset) return res.status(404).json({ error: 'asset not found' });
    const urls = parseOpenApiUrls(s.data.content, asset.base_url);
    if (!urls.length) return res.status(400).json({ error: 'no endpoints parsed (JSON OpenAPI only)' });
    await query('UPDATE asset.assets SET extra_urls=$2 WHERE id=$1', [req.params.id, urls]);
    await audit(req.user!.tenant, req.user!.email, 'asset.openapi_imported', 'asset', req.params.id, { count: urls.length });
    res.json({ endpoints: urls.length });
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


  // ---- User CRUD (admin) ----
  app.patch('/api/v1/users/:id', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    const s = z.object({ name: z.string().optional(), role: z.string().optional(), status: z.enum(['active','disabled']).optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const b = s.data;
    if (req.params.id === req.user!.id && b.status === 'disabled') return res.status(400).json({ error: 'cannot disable your own account' });
    let roleId: string | null = null;
    if (b.role) { const [r] = await query<any>('SELECT id FROM identity.roles WHERE name=$1', [b.role]); if (!r) return res.status(400).json({ error: 'unknown role' }); roleId = r.id; }
    const [row] = await query('UPDATE identity.users SET name=coalesce($3,name), role_id=coalesce($4,role_id), status=coalesce($5,status) WHERE id=$1 AND tenant_id=$2 RETURNING id',
      [req.params.id, req.user!.tenant, b.name || null, roleId, b.status || null]);
    if (!row) return res.status(404).json({ error: 'not found' });
    await audit(req.user!.tenant, req.user!.email, 'user.updated', 'user', req.params.id, b);
    res.json({ ok: true });
  });
  app.post('/api/v1/users/:id/password', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    const s = z.object({ password: z.string().min(8) }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: 'password must be at least 8 characters' });
    const hash = await bcrypt.hash(s.data.password, 10);
    const [row] = await query('UPDATE identity.users SET password_hash=$3 WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, req.user!.tenant, hash]);
    if (!row) return res.status(404).json({ error: 'not found' });
    await audit(req.user!.tenant, req.user!.email, 'user.password_reset', 'user', req.params.id, {});
    res.json({ ok: true });
  });
  app.delete('/api/v1/users/:id', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    if (req.params.id === req.user!.id) return res.status(400).json({ error: 'cannot delete your own account' });
    await query('DELETE FROM identity.users WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user!.tenant]);
    await audit(req.user!.tenant, req.user!.email, 'user.deleted', 'user', req.params.id, {});
    res.json({ ok: true });
  });

  // ---- Role CRUD (admin) ----
  app.post('/api/v1/roles', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    const s = z.object({ name: z.string().min(2), description: z.string().optional(), permissions: z.array(z.string()) }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    try {
      const [row] = await query<any>('INSERT INTO identity.roles(name,description,permissions) VALUES ($1,$2,$3) RETURNING *', [s.data.name, s.data.description || null, s.data.permissions]);
      await audit(req.user!.tenant, req.user!.email, 'role.created', 'role', row.id, { name: s.data.name });
      res.status(201).json(row);
    } catch { res.status(409).json({ error: 'role name already exists' }); }
  });
  app.patch('/api/v1/roles/:id', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    const s = z.object({ description: z.string().optional(), permissions: z.array(z.string()).optional() }).safeParse(req.body);
    if (!s.success) return res.status(400).json({ error: s.error.flatten() });
    const [row] = await query('UPDATE identity.roles SET description=coalesce($2,description), permissions=coalesce($3,permissions) WHERE id=$1 RETURNING id', [req.params.id, s.data.description || null, s.data.permissions || null]);
    if (!row) return res.status(404).json({ error: 'not found' });
    await audit(req.user!.tenant, req.user!.email, 'role.updated', 'role', req.params.id, {});
    res.json({ ok: true });
  });
  app.delete('/api/v1/roles/:id', requireAuth('user:manage'), async (req: AuthedReq, res) => {
    const [u] = await query<any>('SELECT count(*)::int n FROM identity.users WHERE role_id=$1', [req.params.id]);
    if (u.n > 0) return res.status(409).json({ error: `role is in use by ${u.n} user(s)` });
    await query('DELETE FROM identity.roles WHERE id=$1', [req.params.id]);
    await audit(req.user!.tenant, req.user!.email, 'role.deleted', 'role', req.params.id, {});
    res.json({ ok: true });
  });

  return app;
}
