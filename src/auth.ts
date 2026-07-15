import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { query, audit } from './db';
import { config } from './config';

export interface AuthUser { id: string; tenant: string; email: string; name: string; role: string; perms: string[]; }
export interface AuthedReq extends Request { user?: AuthUser; }

export async function login(email: string, password: string) {
  const [u] = await query<any>(
    `SELECT u.*, r.name AS role_name, r.permissions
       FROM identity.users u JOIN identity.roles r ON r.id=u.role_id
      WHERE lower(u.email)=lower($1) AND u.status='active'`, [email]);
  if (!u) throw new Error('invalid credentials');
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) throw new Error('invalid credentials');
  await query('UPDATE identity.users SET last_login_at=now() WHERE id=$1', [u.id]);
  await audit(u.tenant_id, u.email, 'auth.login', 'user', u.id, {});
  const payload = { sub: u.id, tenant: u.tenant_id, email: u.email, name: u.name, role: u.role_name, perms: u.permissions };
  const token = jwt.sign(payload, config.jwtSecret, { expiresIn: config.jwtExpiry } as any);
  return { token, user: { id: u.id, email: u.email, name: u.name, role: u.role_name, perms: u.permissions } };
}

/** Middleware factory: requireAuth() just authenticates; requireAuth('perm') also enforces a permission. */
export function requireAuth(permission?: string) {
  return (req: AuthedReq, res: Response, next: NextFunction) => {
    const h = req.headers.authorization || '';
    let token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) {
      const c = req.headers.cookie || '';
      const found = c.split(';').map(s => s.trim()).find(s => s.startsWith('as_token='));
      if (found) token = decodeURIComponent(found.slice('as_token='.length));
    }
    if (!token) return res.status(401).json({ error: 'authentication required' });
    try {
      const p: any = jwt.verify(token, config.jwtSecret);
      req.user = { id: p.sub, tenant: p.tenant, email: p.email, name: p.name, role: p.role, perms: p.perms || [] };
      if (permission && !req.user.perms.includes(permission)) {
        return res.status(403).json({ error: `forbidden: requires ${permission}` });
      }
      next();
    } catch {
      return res.status(401).json({ error: 'invalid or expired token' });
    }
  };
}
