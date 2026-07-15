import { query } from './db';

export const DEFAULT_SLA: Record<string, Record<string, number>> = {
  Critical: { Critical: 3, High: 7, Medium: 14, Low: 30, Info: 90 },
  High:     { Critical: 7, High: 7, Medium: 30, Low: 60, Info: 120 },
  Medium:   { Critical: 7, High: 15, Medium: 45, Low: 90, Info: 180 },
  Low:      { Critical: 15, High: 30, Medium: 60, Low: 120, Info: 365 },
};

export async function getSetting<T = any>(key: string, def: T): Promise<T> {
  try { const [r] = await query<any>('SELECT value FROM vapt.settings WHERE key=$1', [key]); return r ? r.value : def; }
  catch { return def; }
}
export async function setSetting(key: string, value: any) {
  await query('INSERT INTO vapt.settings(key,value,updated_at) VALUES ($1,$2,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()', [key, JSON.stringify(value)]);
}
export function slaDaysFor(policy: any, severity: string, criticality?: string): number {
  const p = policy || DEFAULT_SLA;
  const row = p[criticality || 'High'] || p.High || DEFAULT_SLA.High;
  const d = row[severity];
  return typeof d === 'number' ? d : (severity === 'Critical' || severity === 'High' ? 7 : 90);
}
