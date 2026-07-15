import { Finding, Severity } from './types';

const dec = (s: string) => (s || '')
  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
  .replace(/\s+/g, ' ').trim();
const tag = (xml: string, name: string) => { const m = xml.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i')); return m ? dec(m[1]) : undefined; };
const attr = (s: string, name: string) => { const m = s.match(new RegExp(`${name}="([^"]*)"`, 'i')); return m ? m[1] : undefined; };
const numSev = (n: number): Severity => ['Info', 'Low', 'Medium', 'High', 'Critical'][Math.max(0, Math.min(4, n))] as Severity;
const wordSev = (w: string): Severity => { const x = (w || '').toLowerCase();
  if (x.startsWith('crit')) return 'Critical'; if (x === 'high') return 'High';
  if (x === 'medium' || x === 'moderate') return 'Medium'; if (x === 'low') return 'Low'; return 'Info'; };

// ---- Nessus (.nessus XML) ----
export function parseNessus(x: string): Finding[] {
  const out: Finding[] = [];
  const items = x.match(/<ReportItem\b[\s\S]*?<\/ReportItem>/gi) || [];
  for (const it of items) {
    const sev = numSev(parseInt(attr(it, 'severity') || '0', 10));
    const name = attr(it, 'pluginName') || tag(it, 'plugin_name') || 'Nessus finding';
    const cvss = parseFloat(tag(it, 'cvss3_base_score') || tag(it, 'cvss_base_score') || '') || undefined;
    const cve = tag(it, 'cve');
    out.push({ title: name, severity: sev, category: 'vulnerability', scanner: 'nessus', source: 'import:nessus',
      description: tag(it, 'description'), remediation: tag(it, 'solution'),
      cvss, cve, cvssVector: tag(it, 'cvss3_vector') || tag(it, 'cvss_vector'),
      cwe: (tag(it, 'cwe') ? 'CWE-' + tag(it, 'cwe') : undefined),
      refs: [tag(it, 'see_also')].filter(Boolean) as string[],
      evidence: { port: attr(it, 'port'), service: attr(it, 'svc_name'), plugin: attr(it, 'pluginID') } });
  }
  return out;
}

// ---- Nmap XML ----
export function parseNmap(x: string): Finding[] {
  const out: Finding[] = [];
  const re = /<port protocol="(\w+)" portid="(\d+)">\s*<state state="open"[^>]*\/>\s*(?:<service name="([^"]*)"(?:[^>]*product="([^"]*)")?)?/g;
  let m; while ((m = re.exec(x)) !== null) {
    const [, proto, port, svc, prod] = m;
    out.push({ title: `Open port ${port}/${proto}${svc ? ' (' + svc + ')' : ''}`, severity: 'Info', category: 'network', scanner: 'nmap', source: 'import:nmap',
      description: `Service exposed${prod ? ': ' + prod : ''}.`, remediation: 'Restrict exposure via firewall/security groups; disable unused services.',
      evidence: { port, proto, service: svc, product: prod } });
  }
  return out;
}

// ---- OWASP ZAP JSON ----
export function parseZap(text: string): Finding[] {
  const out: Finding[] = []; const rep = JSON.parse(text);
  const risk: any = { '3': 'High', '2': 'Medium', '1': 'Low', '0': 'Info' };
  for (const s of (rep.site || [])) for (const a of (s.alerts || [])) {
    out.push({ title: a.name || a.alert, severity: risk[a.riskcode] || 'Info', category: 'vulnerability', scanner: 'zap', source: 'import:zap',
      description: dec(a.desc), remediation: dec(a.solution), cwe: a.cweid ? `CWE-${a.cweid}` : undefined,
      refs: a.reference ? [dec(a.reference)] : [], evidence: { instances: (a.instances || []).length } });
  }
  return out;
}

// ---- Burp Suite XML ----
export function parseBurp(x: string): Finding[] {
  const out: Finding[] = [];
  const issues = x.match(/<issue>[\s\S]*?<\/issue>/gi) || [];
  for (const it of issues) {
    out.push({ title: tag(it, 'name') || 'Burp issue', severity: wordSev(tag(it, 'severity') || ''), category: 'vulnerability', scanner: 'burp', source: 'import:burp',
      description: tag(it, 'issueBackground') || tag(it, 'issueDetail'), remediation: tag(it, 'remediationBackground'),
      cwe: (tag(it, 'vulnerabilityClassifications') || '').match(/CWE-\d+/)?.[0],
      evidence: { host: tag(it, 'host'), path: tag(it, 'path') } });
  }
  return out;
}

// ---- SARIF (SAST/DAST JSON) ----
export function parseSarif(text: string): Finding[] {
  const out: Finding[] = []; const rep = JSON.parse(text);
  const lvl: any = { error: 'High', warning: 'Medium', note: 'Low', none: 'Info' };
  for (const run of (rep.runs || [])) {
    const rules: any = {};
    for (const r of (run.tool?.driver?.rules || [])) rules[r.id] = r;
    for (const res of (run.results || [])) {
      const rule = rules[res.ruleId] || {};
      const ss = parseFloat(rule.properties?.['security-severity'] || '');
      const sev: Severity = !isNaN(ss) ? (ss >= 9 ? 'Critical' : ss >= 7 ? 'High' : ss >= 4 ? 'Medium' : ss > 0 ? 'Low' : 'Info') : (lvl[res.level] || 'Medium');
      out.push({ title: (rule.shortDescription?.text || res.ruleId || res.message?.text || 'SARIF result').slice(0, 160), severity: sev,
        category: 'vulnerability', scanner: 'sarif', source: 'import:sarif', description: res.message?.text || rule.fullDescription?.text,
        remediation: rule.help?.text, cvss: !isNaN(ss) ? ss : undefined,
        cwe: (Array.isArray(rule.properties?.tags) ? rule.properties.tags.find((t: string) => /cwe-\d+/i.test(t)) : undefined),
        evidence: { rule: res.ruleId, location: res.locations?.[0]?.physicalLocation?.artifactLocation?.uri } });
    }
  }
  return out;
}

export type ImportFormat = 'nessus' | 'nmap' | 'zap' | 'burp' | 'sarif';
export function detectFormat(c: string): ImportFormat | null {
  const t = c.trimStart();
  if (t.startsWith('{')) { if (/"runs"\s*:/.test(c) && /"version"/.test(c)) return 'sarif'; if (/"site"\s*:|"alerts"\s*:/.test(c)) return 'zap'; return null; }
  if (t.startsWith('<')) { if (/NessusClientData|<ReportItem/i.test(c)) return 'nessus'; if (/<nmaprun/i.test(c)) return 'nmap'; if (/<issues|burp/i.test(c) || /<issue>/i.test(c)) return 'burp'; }
  return null;
}
export function parseImport(format: ImportFormat, content: string): Finding[] {
  switch (format) {
    case 'nessus': return parseNessus(content);
    case 'nmap': return parseNmap(content);
    case 'zap': return parseZap(content);
    case 'burp': return parseBurp(content);
    case 'sarif': return parseSarif(content);
    default: return [];
  }
}


// ---- OpenAPI / Swagger -> list of endpoint URLs ----
export function parseOpenApiUrls(content: string, baseUrl?: string): string[] {
  let spec: any;
  try { spec = JSON.parse(content); } catch { return []; }   // JSON specs only
  const servers: string[] = (spec.servers || []).map((s: any) => s.url).filter(Boolean);
  const base = (servers[0] || baseUrl || '').replace(/\/$/, '');
  const urls: string[] = [];
  for (const p of Object.keys(spec.paths || {})) {
    const path = p.replace(/\{[^}]+\}/g, '1');
    try { urls.push(new URL(base + path).toString()); }
    catch { try { if (baseUrl) urls.push(new URL(path, baseUrl).toString()); } catch { /* skip */ } }
  }
  return [...new Set(urls)].slice(0, 200);
}
