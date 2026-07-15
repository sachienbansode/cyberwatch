import * as tls from 'tls';
import { Scanner, ScanContext, Finding } from '../types';

const _fetch: any = (globalThis as any).fetch;

function add(out: Finding[], f: Finding) { out.push(f); }

async function getHeaders(url: string): Promise<{ status: number; headers: any; setCookies: string[] } | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    const res = await _fetch(url, { redirect: 'follow', signal: ctrl.signal, headers: { 'User-Agent': 'AntShield-VAPT/1.0 (+passive)' } });
    clearTimeout(t);
    const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    return { status: res.status, headers: res.headers, setCookies };
  } catch { return null; }
}

function tlsInfo(host: string): Promise<{ protocol: string | null; validTo: string; daysLeft: number } | null> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host, timeout: 12000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const validTo = cert && cert.valid_to ? cert.valid_to : '';
      const daysLeft = validTo ? Math.round((new Date(validTo).getTime() - Date.now()) / 86400000) : 0;
      socket.end();
      resolve({ protocol, validTo, daysLeft });
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

export const passiveScanner: Scanner = {
  key: 'passive',
  kind: 'passive',
  async available() { return true; },
  async run(ctx: ScanContext): Promise<Finding[]> {
    const out: Finding[] = [];
    const url = ctx.targetUrl;
    const isHttps = url.startsWith('https://');

    // 1. HTTPS enforcement (non-intrusive: just observe redirect behaviour)
    const httpUrl = url.replace(/^https?:\/\//, 'http://');
    try {
      const r = await _fetch(httpUrl, { redirect: 'manual', headers: { 'User-Agent': 'AntShield-VAPT/1.0' } });
      const loc = r.headers.get('location') || '';
      if (!(r.status >= 300 && r.status < 400 && loc.startsWith('https://'))) {
        add(out, { title: 'HTTP not redirected to HTTPS', severity: 'Medium', category: 'tls', scanner: 'passive',
          description: 'Plain-HTTP requests are not redirected to HTTPS, allowing cleartext access.',
          remediation: 'Force a 301 redirect from HTTP to HTTPS and enable HSTS.', cwe: 'CWE-319' });
      }
    } catch { /* http may be closed — acceptable */ }

    // 2. Response headers
    const resp = await getHeaders(url);
    if (!resp) {
      add(out, { title: 'Target unreachable during passive scan', severity: 'Info', category: 'info', scanner: 'passive',
        description: `Could not retrieve ${url}. Verify the URL and network reachability from the scanner host.` });
      return out;
    }
    const h = resp.headers;
    const has = (name: string) => !!h.get(name);

    const headerChecks: [string, string, Finding['severity'], string, string][] = [
      ['strict-transport-security', 'Missing HSTS header', 'Medium', 'headers',
        'Add Strict-Transport-Security with a long max-age and includeSubDomains.'],
      ['content-security-policy', 'Missing Content-Security-Policy', 'Medium', 'headers',
        'Define a restrictive CSP to mitigate XSS and data injection.'],
      ['x-content-type-options', 'Missing X-Content-Type-Options: nosniff', 'Low', 'headers',
        'Set X-Content-Type-Options: nosniff.'],
      ['x-frame-options', 'Missing clickjacking protection (X-Frame-Options / frame-ancestors)', 'Low', 'headers',
        'Set X-Frame-Options: DENY or a CSP frame-ancestors directive.'],
      ['referrer-policy', 'Missing Referrer-Policy', 'Low', 'headers',
        'Set a privacy-preserving Referrer-Policy (e.g. strict-origin-when-cross-origin).'],
      ['permissions-policy', 'Missing Permissions-Policy', 'Info', 'headers',
        'Restrict powerful browser features via Permissions-Policy.'],
    ];
    for (const [name, title, sev, cat, rem] of headerChecks) {
      if (!has(name)) add(out, { title, severity: sev, category: cat, scanner: 'passive', remediation: rem });
    }
    if (!isHttps && has('content-security-policy')) { /* no-op */ }

    // 3. Server banner / tech disclosure
    const banner = [h.get('server'), h.get('x-powered-by')].filter(Boolean).join('; ');
    if (banner) add(out, { title: 'Server/technology banner disclosed', severity: 'Low', category: 'exposure', scanner: 'passive',
      description: `Response advertises: ${banner}`, remediation: 'Suppress or genericise Server and X-Powered-By headers.', evidence: { banner } });

    // 4. Cookie flags
    for (const c of resp.setCookies) {
      const lc = c.toLowerCase();
      const name = c.split('=')[0];
      const missing = [!lc.includes('secure') && 'Secure', !lc.includes('httponly') && 'HttpOnly', !lc.includes('samesite') && 'SameSite'].filter(Boolean);
      if (missing.length) add(out, { title: `Cookie '${name}' missing ${missing.join(', ')} flag(s)`, severity: 'Medium', category: 'cookies', scanner: 'passive',
        description: 'Session/security cookies lack protective attributes.', remediation: 'Set Secure, HttpOnly and SameSite on sensitive cookies.', cwe: 'CWE-614', evidence: { cookie: name } });
    }

    // 5. TLS protocol & certificate (observation only)
    if (isHttps) {
      const info = await tlsInfo(ctx.host);
      if (info) {
        if (info.protocol && /TLSv1(\.1)?$/.test(info.protocol)) {
          add(out, { title: `Weak TLS protocol negotiated (${info.protocol})`, severity: 'High', category: 'tls', scanner: 'passive',
            description: 'The server negotiated a deprecated TLS version.', remediation: 'Disable TLS 1.0/1.1; require TLS 1.2+.', cwe: 'CWE-326', evidence: { protocol: info.protocol } });
        }
        if (info.daysLeft <= 0) add(out, { title: 'TLS certificate expired', severity: 'High', category: 'tls', scanner: 'passive', evidence: { validTo: info.validTo } });
        else if (info.daysLeft <= 21) add(out, { title: `TLS certificate expiring soon (${info.daysLeft} days)`, severity: 'Medium', category: 'tls', scanner: 'passive', evidence: { validTo: info.validTo } });
      }
    }

    // 6. security.txt presence (RFC 9116) — informational hygiene
    const st = await _fetch(new URL('/.well-known/security.txt', url).toString(), { redirect: 'follow' }).then((r: any) => r.status).catch(() => 0);
    if (st !== 200) add(out, { title: 'No security.txt disclosure policy', severity: 'Info', category: 'exposure', scanner: 'passive',
      description: 'No /.well-known/security.txt was found.', remediation: 'Publish a security.txt with a disclosure contact (RFC 9116).' });


    // 7. CORS policy (send a cross-origin Origin and observe reflection)
    try {
      const cr = await _fetch(url, { headers: { 'User-Agent': 'AntShield-VAPT/1.0', 'Origin': 'https://antshield-probe.example' }, redirect: 'manual' });
      const acao = cr.headers.get('access-control-allow-origin');
      const acac = cr.headers.get('access-control-allow-credentials');
      if (acao === '*') add(out, { title: 'Permissive CORS policy (Access-Control-Allow-Origin: *)', severity: 'Low', category: 'headers', scanner: 'passive', description: 'Any website can read responses from this origin.', remediation: 'Restrict CORS to an allowlist of trusted origins.', cwe: 'CWE-942' });
      else if (acao === 'https://antshield-probe.example') add(out, { title: 'CORS reflects an arbitrary Origin', severity: acac === 'true' ? 'High' : 'Medium', category: 'headers', scanner: 'passive', description: 'The server echoes the request Origin' + (acac === 'true' ? ' and allows credentials, enabling cross-origin theft of authenticated data' : ''), remediation: 'Validate Origin against a strict allowlist; never reflect arbitrary origins, especially with credentials.', cwe: 'CWE-942' });
    } catch { /* CORS probe best-effort */ }

    // 8. Dangerous HTTP methods
    try {
      const opt = await _fetch(url, { method: 'OPTIONS', redirect: 'manual' });
      const allow = (opt.headers.get('allow') || opt.headers.get('access-control-allow-methods') || '').toUpperCase();
      const risky = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT'].filter(m => allow.includes(m));
      if (risky.length) add(out, { title: 'Potentially dangerous HTTP methods enabled: ' + risky.join(', '), severity: 'Low', category: 'exposure', scanner: 'passive', description: 'The server advertises HTTP methods that are rarely needed and can enable attacks (e.g. XST via TRACE).', remediation: 'Disable unused HTTP methods at the web server / WAF.', evidence: { allow } });
    } catch { /* methods probe best-effort */ }

    // 9. Exposed sensitive files (safe GET to well-known paths, signature-verified)
    const probes: [string, Finding['severity'], (b: string) => boolean][] = [
      ['/.git/HEAD', 'High', b => /^ref:\s/.test(b.trim())],
      ['/.env', 'High', b => /^[A-Z0-9_]+=.*/m.test(b) && /(SECRET|KEY|PASSWORD|PASSWD|TOKEN|DB_|DATABASE|API)/i.test(b)],
      ['/server-status', 'Medium', b => /Apache Server Status|Server uptime|Total accesses/i.test(b)],
      ['/.svn/entries', 'High', b => /^\d+|dir|svn:/i.test(b.trim())],
    ];
    for (const [pth, sev, ok] of probes) {
      try {
        const rr = await _fetch(new URL(pth, url).toString(), { redirect: 'manual', headers: { 'User-Agent': 'AntShield-VAPT/1.0' } });
        if (rr.status === 200) {
          const body = (await rr.text().catch(() => '')).slice(0, 4000);
          if (ok(body)) add(out, { title: 'Exposed sensitive path: ' + pth, severity: sev, category: 'exposure', scanner: 'passive', description: 'A sensitive file is publicly accessible and may leak source code, credentials or configuration.', remediation: 'Block public access to ' + pth + ' at the web server and remove it from the web root.', cwe: 'CWE-538', evidence: { path: pth } });
        }
      } catch { /* probe best-effort */ }
    }

    // 10. CSP quality
    const csp = h.get('content-security-policy');
    if (csp && /unsafe-inline|unsafe-eval|\*/.test(csp)) add(out, { title: 'Weak Content-Security-Policy (uses unsafe-inline / unsafe-eval / wildcard)', severity: 'Low', category: 'headers', scanner: 'passive', description: 'The CSP contains directives that substantially weaken its XSS protection.', remediation: "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces or hashes.", cwe: 'CWE-693' });

    return out;
  },
};
