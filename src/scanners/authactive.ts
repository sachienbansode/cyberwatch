import { Scanner, ScanContext, Finding, AuthConfig } from '../types';
const _fetch: any = (globalThis as any).fetch;
const UA = 'AntShield-VAPT/1.0 (authorized active scan)';

// ---- pure, unit-testable detectors ----
export function sqlErrorSignature(body: string): boolean {
  return /SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{4,}|PostgreSQL.*ERROR|PG::SyntaxError|SQLite\/JDBC|SQLServer JDBC|Unclosed quotation mark|quoted string not properly terminated|syntax error at or near/i.test(body || '');
}
export function reflects(body: string, marker: string): boolean { return (body || '').includes(marker); }
export function isRedirectParam(name: string): boolean { return /^(redirect|redirect_uri|url|next|return|returnurl|return_url|dest|destination|continue|goto|to|u)$/i.test(name); }
export function extractLinks(html: string, base: string, host: string): string[] {
  const out = new Set<string>(); const re = /href=["']([^"'#]+)["']/gi; let m;
  while ((m = re.exec(html)) !== null) {
    try { const u = new URL(m[1], base); if (u.hostname === host && /^https?:/.test(u.protocol)) { u.hash = ''; out.add(u.toString()); } } catch { /* skip */ }
  }
  return [...out];
}

async function establish(auth?: AuthConfig): Promise<Record<string, string>> {
  if (!auth || auth.method === 'none') return {};
  const ex = auth.extra || {};
  if (auth.method === 'bearer') return { Authorization: 'Bearer ' + (auth.secret || '') };
  if (auth.method === 'cookie') return { Cookie: auth.secret || '' };
  if (auth.method === 'header') return { [ex.headerName || 'Authorization']: auth.secret || '' };
  if (auth.method === 'form' && auth.loginUrl) {
    try {
      const body = new URLSearchParams({ [ex.userField || 'username']: auth.username || '', [ex.passField || 'password']: auth.secret || '' }).toString();
      const r = await _fetch(auth.loginUrl, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', 'User-Agent': UA }, body });
      const sc = typeof r.headers.getSetCookie === 'function' ? r.headers.getSetCookie() : [];
      if (sc.length) return { Cookie: sc.map((c: string) => c.split(';')[0]).join('; ') };
    } catch { /* login best-effort */ }
  }
  return {};
}
const get = (url: string, headers: any, redirect: 'follow' | 'manual' = 'follow') =>
  _fetch(url, { redirect, headers: { 'User-Agent': UA, ...headers }, signal: AbortSignal.timeout(12000) });

export const authActiveScanner: Scanner = {
  key: 'auth-active', kind: 'active',
  async available() { return true; },
  async run(ctx: ScanContext): Promise<Finding[]> {
    const out: Finding[] = [];
    const headers = await establish(ctx.auth);
    if (Object.keys(headers).length) out.push({ title: 'Authenticated scan session established', severity: 'Info', category: 'info', scanner: 'auth-active', description: `Active scan ran as an authenticated session (${ctx.auth?.method}).` });

    // ---- crawl (authenticated), same-origin, bounded ----
    const seen = new Set<string>(); const queue: string[] = [ctx.targetUrl, ...(ctx.extraUrls || [])];
    const targets: string[] = [];
    let budget = 25;
    while (queue.length && budget-- > 0) {
      const u = queue.shift()!; if (seen.has(u)) continue; seen.add(u);
      try {
        const r = await get(u, headers);
        const body = await r.text().catch(() => '');
        targets.push(u);
        for (const l of extractLinks(body, u, ctx.host)) if (!seen.has(l) && queue.length < 60) queue.push(l);
      } catch { /* skip */ }
    }
    const withParams = [...new Set(targets)].filter(u => { try { return [...new URL(u).searchParams.keys()].length > 0; } catch { return false; } }).slice(0, 30);

    // ---- detection-grade active checks (non-destructive markers only) ----
    for (const u of withParams) {
      const url = new URL(u);
      for (const p of [...url.searchParams.keys()]) {
        // Reflected XSS (unique marker with angle brackets)
        try {
          const marker = 'axs9271<z>'; const t = new URL(url.toString()); t.searchParams.set(p, marker);
          const r = await get(t.toString(), headers); const b = await r.text().catch(() => '');
          if (reflects(b, marker)) out.push({ title: `Reflected input without output-encoding in parameter "${p}"`, severity: 'High', category: 'injection', scanner: 'auth-active', cwe: 'CWE-79',
            description: `The value of "${p}" is reflected into the response unencoded, indicating a potential reflected XSS.`, remediation: 'Context-aware output encoding; apply a strict Content-Security-Policy.', evidence: { url: t.toString(), parameter: p, marker } });
        } catch { /* */ }
        // SQL error-based
        try {
          const t = new URL(url.toString()); t.searchParams.set(p, (url.searchParams.get(p) || '1') + "'");
          const r = await get(t.toString(), headers); const b = await r.text().catch(() => '');
          if (sqlErrorSignature(b)) out.push({ title: `Possible SQL injection (database error) in parameter "${p}"`, severity: 'Critical', category: 'injection', scanner: 'auth-active', cwe: 'CWE-89',
            description: `Injecting a single quote into "${p}" elicited a database error, indicating unsanitised input reaching a SQL query.`, remediation: 'Use parameterised queries / prepared statements; validate input; least-privilege DB accounts.', evidence: { url: t.toString(), parameter: p } });
        } catch { /* */ }
        // Open redirect
        if (isRedirectParam(p)) {
          try {
            const probe = 'https://antshield-probe.example/'; const t = new URL(url.toString()); t.searchParams.set(p, probe);
            const r = await get(t.toString(), headers, 'manual'); const loc = r.headers.get('location') || '';
            if (loc.startsWith(probe) || loc.startsWith('//antshield-probe.example')) out.push({ title: `Open redirect via parameter "${p}"`, severity: 'Medium', category: 'vulnerability', scanner: 'auth-active', cwe: 'CWE-601',
              description: `"${p}" redirects to an attacker-controlled external URL without validation.`, remediation: 'Allowlist redirect destinations; use relative paths or mapping keys.', evidence: { url: t.toString(), parameter: p, location: loc } });
          } catch { /* */ }
        }
      }
    }
    out.push({ title: 'Authenticated active crawl completed', severity: 'Info', category: 'info', scanner: 'auth-active', description: `Crawled ${targets.length} URL(s); actively tested ${withParams.length} parameterised endpoint(s).`, evidence: { crawled: targets.length, tested: withParams.length } });
    return out;
  },
};
