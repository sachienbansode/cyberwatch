import { Pool, PoolClient } from 'pg';
import { config } from './config';

export const pool = new Pool(config.pg);

export async function query<T = any>(text: string, params: any[] = []): Promise<T[]> {
  const r = await pool.query(text, params);
  return r.rows as T[];
}

/** Run fn inside a transaction with the tenant GUC set (drives row-level security). */
export async function withTenant<T>(tenantId: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

export async function audit(tenantId: string | null, actor: string, action: string, entity?: string, entityId?: string, detail: any = {}) {
  try {
    await pool.query(
      'INSERT INTO audit.audit_log(tenant_id,actor,action,entity,entity_id,detail) VALUES ($1,$2,$3,$4,$5,$6)',
      [tenantId, actor, action, entity || null, entityId || null, detail]
    );
  } catch { /* audit must never break the main flow */ }
}
