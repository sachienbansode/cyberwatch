import { Scanner, ScanContext, Finding, Severity } from '../types';
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
    const html = await get(ctx.targetUrl);
    const out: Finding[] = [];
    out.push(...scanSecrets(html, ctx.targetUrl));
    // same-origin script sources
    const scripts = new Set<string>(); const re = /<script[^>]+src=["']([^"']+)["']/gi; let m;
    while ((m = re.exec(html)) !== null && scripts.size < 15) {
      try { const u = new URL(m[1], ctx.targetUrl); if (u.hostname === ctx.host) scripts.add(u.toString()); } catch { /* */ }
    }
    for (const s of scripts) { const js = await get(s); if (js) out.push(...scanSecrets(js, s)); }
    return out;
  },
};
