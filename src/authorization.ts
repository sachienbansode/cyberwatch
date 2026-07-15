import { query } from './db';
import { config } from './config';

export class AuthorizationError extends Error {}

/**
 * Hard gate for active/intrusive testing. Requires BOTH:
 *   1) the global kill-switch ACTIVE_SCANS_ENABLED=true, and
 *   2) a stored, unexpired scan_authorization whose scope_hosts includes the target host.
 */
export async function assertActiveAuthorized(assetId: string, host: string) {
  if (!config.activeScansEnabled) {
    throw new AuthorizationError('Active scanning is disabled. Set ACTIVE_SCANS_ENABLED=true only for systems you are authorised to test.');
  }
  const rows = await query<any>(
    `SELECT * FROM vapt.scan_authorizations
       WHERE asset_id=$1 AND active=true AND expires_at > now()`, [assetId]);
  const auth = rows.find(a => (a.scope_hosts || []).map((x: string) => x.toLowerCase()).includes(host.toLowerCase()));
  if (!auth) {
    throw new AuthorizationError(`No active, in-scope authorization for host "${host}". Record one (POST /api/v1/assets/:id/authorizations) before active testing.`);
  }
  return auth;
}
