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

    return out;
  },
};
