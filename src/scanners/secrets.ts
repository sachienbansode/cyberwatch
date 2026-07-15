import { Scanner, ScanContext, Finding, Severity } from '../types';
import { config } from '../config';
const _fetch: any = (globalThis as any).fetch;
const UA = 'AntShield-VAPT/1.0';

function redact(s: string): string {
  s = s.replace(/\s+/g, ' ').trim();
  if (s.length <= 12) return s.slice(0, 3) + '****';
  return s.slice(0, 5) + '…' + '*'.repeat(6) + '…' + s.slice(-4);
}
const FP = /^(true|false|null|undefined|yes|no|none|change[_-]?me|your[_-]?|example|placeholder|xxx+|test|demo|sample|\$\{|process\.env|import\.meta)/i;

interface Pat { name: string; re: RegExp; sev: Severity; grp?: number; }
const PATTERNS: Pat[] = [
  { name: 'Private cryptographic key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, sev: 'Critical' },
  { name: 'AWS secret access key', re: /aws_secret_access_key["'\s:=]+([A-Za-z0-9/+]{40})/gi, sev: 'Critical', grp: 1 },
  { name: 'AWS access key ID', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, sev: 'High' },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, sev: 'High' },
  { name: 'Stripe live secret key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g, sev: 'Critical' },
  { name: 'Slack token', re: /\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b/g, sev: 'High' },
  { name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b/g, sev: 'High' },
  { name: 'GitHub fine-grained PAT', re: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/g, sev: 'High' },
  { name: 'Twilio API key', re: /\bSK[0-9a-fA-F]{32}\b/g, sev: 'High' },
  { name: 'Database connection string with credentials', re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^/\s:@"']+:[^/\s:@"']+@[^\s"']+/gi, sev: 'Critical' },
  { name: 'Credentials embedded in URL', re: /\b(?:https?|ftp):\/\/[^/\s:@"']+:[^/\s:@"']+@[^\s"']+/g, sev: 'High' },
  { name: 'Hardcoded JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/g, sev: 'Medium' },
  { name: 'Auth token stored in browser storage', re: /(?:localStorage|sessionStorage)\.setItem\(\s*["'][^"']*(?:token|jwt|auth|session|secret|password)[^"']*["']/gi, sev: 'Medium' },
  { name: 'Hardcoded secret/API key assignment', re: /["']?(?:api[_-]?key|apikey|secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?token|password|passwd|pwd)["']?\s*[:=]\s*["']([^"'${}\s]{8,64})["']/gi, sev: 'Medium', grp: 1 },
];

/** Pure secret scan over a blob of text. Returns findings keyed by (type + redacted). */
export function scanSecrets(content: string, sourceUrl: string): Finding[] {
  const out: Finding[] = []; const seen = new Set<string>();
  for (const p of PATTERNS) {
    p.re.lastIndex = 0; let m: RegExpExecArray | null;
    while ((m = p.re.exec(content)) !== null) {
      const val = (p.grp ? m[p.grp] : m[0]) || '';
      if (p.grp && (FP.test(val) || /\s/.test(val))) continue;
      const key = p.name + '|' + redact(val);
      if (seen.has(key)) continue; seen.add(key);
      out.push({
        title: p.name === 'Auth token stored in browser storage'
          ? 'Authentication token stored in browser storage (XSS-exfiltratable)'
          : 'Secret exposed in client-side code: ' + p.name,
        severity: p.sev, category: 'secrets', scanner: 'secrets', cwe: 'CWE-798',
        description: 'A secret or credential is present in content served to the browser, and is visible to anyone via View Source or DevTools.',
        remediation: 'Never embed secrets in front-end code. Move them server-side, use short-lived scoped tokens, and rotate any exposed key immediately.',
        evidence: { url: sourceUrl, type: p.name, match: redact(m[0]) },
      });
      if (out.length > 60) return out;
    }
  }
  return out;
}

export const secretsScanner: Scanner = {
  key: 'secrets', kind: 'passive',
  async available() { return true; },
  async run(ctx: ScanContext): Promise<Finding[]> {
    const get = async (u: string) => {
      try { const r = await _fetch(u, { redirect: 'follow', headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(12000) }); return r.ok ? await r.text() : ''; }
      catch { return ''; }
    };
    const host = ctx.host;
    const maxPages = config.crawlMaxPages || 25;
    const out: Finding[] = [];
    const seen = new Set<string>(); const jsSeen = new Set<string>();
    const queue: string[] = [ctx.targetUrl, ...(ctx.extraUrls || [])];

    // discover URLs from robots.txt and sitemap.xml (finds pages not linked from the homepage)
    try {
      const robots = await get(new URL('/robots.txt', ctx.targetUrl).toString());
      const sitemaps = [...robots.matchAll(/sitemap:\s*(\S+)/gi)].map(m => m[1]);
      sitemaps.push(new URL('/sitemap.xml', ctx.targetUrl).toString());
      for (const sm of sitemaps.slice(0, 2)) {
        const xml = await get(sm);
        for (const m of xml.matchAll(/<loc>([^<]+)<\/loc>/gi)) { try { if (new URL(m[1]).hostname === host) queue.push(m[1]); } catch { /* */ } }
      }
    } catch { /* discovery best-effort */ }

    // crawl same-origin pages, scan each page's HTML + linked JS
    let pages = 0;
    while (queue.length && pages < maxPages) {
      const u = queue.shift()!; if (seen.has(u)) continue; seen.add(u);
      const html = await get(u); if (!html) continue; pages++;
      out.push(...scanSecrets(html, u));
      for (const m of html.matchAll(/href=["']([^"'#?]+)["']/gi)) {
        try { const l = new URL(m[1], u); l.hash = ''; if (l.hostname === host && !seen.has(l.toString()) && queue.length < 300) queue.push(l.toString()); } catch { /* */ }
      }
      for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
        try {
          const j = new URL(m[1], u).toString();
          if (new URL(j).hostname === host && !jsSeen.has(j) && jsSeen.size < 60) { jsSeen.add(j); const js = await get(j); if (js) out.push(...scanSecrets(js, j)); }
        } catch { /* */ }
      }
    }
    // de-duplicate identical secrets across pages
    const uniq = new Map<string, Finding>();
    for (const f of out) { const k = f.title + '|' + ((f.evidence as any)?.match || '') + '|' + ((f.evidence as any)?.url || ''); if (!uniq.has(k)) uniq.set(k, f); }
    return [...uniq.values()];
  },
};
