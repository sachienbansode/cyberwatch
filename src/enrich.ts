import { Severity } from './types';
const _fetch: any = (globalThis as any).fetch;

// ---- CISA Known Exploited Vulnerabilities (cached) ----
let kevSet: Set<string> | null = null;
let kevAt = 0;
async function kev(): Promise<Set<string>> {
  if (kevSet && Date.now() - kevAt < 12 * 3600_000) return kevSet;
  try {
    const r = await _fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { signal: AbortSignal.timeout(15000) });
    const j = await r.json();
    kevSet = new Set((j.vulnerabilities || []).map((v: any) => (v.cveID || '').toUpperCase()));
    kevAt = Date.now();
  } catch { if (!kevSet) kevSet = new Set(); }
  return kevSet;
}

// ---- EPSS (exploit prediction) ----
async function epss(cve: string): Promise<number | null> {
  try {
    const r = await _fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`, { signal: AbortSignal.timeout(12000) });
    const j = await r.json();
    const v = j.data && j.data[0] && j.data[0].epss;
    return v != null ? parseFloat(v) : null;
  } catch { return null; }
}

const sevCvss = (s: Severity) => ({ Critical: 9, High: 7.5, Medium: 5, Low: 3, Info: 1 }[s] || 1);
const critMul = (c: string) => ({ Critical: 1, High: 0.92, Medium: 0.82, Low: 0.68 } as any)[c] || 0.85;

export function bandOf(score: number): Severity {
  return score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 40 ? 'Medium' : score >= 20 ? 'Low' : 'Info';
}

/** Contextual risk score 0-100 from CVSS, EPSS, KEV and asset criticality. */
export function riskScore(opts: { cvss?: number; severity: Severity; epss?: number | null; kev?: boolean; assetCriticality?: string }): number {
  const base = (opts.cvss && opts.cvss > 0 ? opts.cvss : sevCvss(opts.severity)) * 10;   // 0-100
  let s = base;
  if (opts.kev) s = Math.max(s, 85) + 8;                 // known-exploited dominates
  if (opts.epss != null) s += opts.epss * 15;            // exploit likelihood
  s = s * critMul(opts.assetCriticality || 'High');      // business context
  return Math.round(Math.max(0, Math.min(100, s)));
}

export async function enrichFinding(f: { cve?: string; cvss?: number; severity: Severity }, assetCriticality?: string) {
  let e: number | null = null, k = false;
  if (f.cve) {
    const cveU = f.cve.toUpperCase().match(/CVE-\d{4}-\d+/)?.[0];
    if (cveU) { [e, k] = await Promise.all([epss(cveU), kev().then(set => set.has(cveU))]); }
  }
  const risk = riskScore({ cvss: f.cvss, severity: f.severity, epss: e, kev: k, assetCriticality });
  return { epss: e, kev: k, risk_score: risk };
}
