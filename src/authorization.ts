import { query } from './db';
import { getSetting } from './settings';

export class AuthorizationError extends Error {}

/**
 * Active/intrusive testing gate. Requires:
 *   1) active scanning not locked org-wide by an administrator, and
 *   2) a valid, unexpired authorization record whose scope includes the host
 *      (created when a user accepts the active-scan authorization terms for the asset).
 */
export async function assertActiveAuthorized(assetId: string, host: string) {
  const locked = await getSetting<boolean>('active_scans_locked', false);
  if (locked) throw new AuthorizationError('Active scanning is currently locked organisation-wide by an administrator.');
  const rows = await query<any>(
    `SELECT * FROM vapt.scan_authorizations WHERE asset_id=$1 AND active=true AND expires_at > now()`, [assetId]);
  const auth = rows.find(a => (a.scope_hosts || []).map((x: string) => x.toLowerCase()).includes(host.toLowerCase()));
  if (!auth) throw new AuthorizationError(`Active scanning is not enabled for "${host}". Open the asset and enable active scanning (accept the authorization terms) first.`);
  return auth;
}
