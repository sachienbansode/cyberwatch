import { spawn } from 'child_process';
import * as fs from 'fs';
import { Scanner, ScanContext, Finding } from '../types';
import { config } from '../config';

function run(cmd: string, args: string[], timeoutMs: number): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    let stdout = '', stderr = '';
    let child;
    try { child = spawn(cmd, args, { shell: false }); }
    catch { return resolve({ code: -1, stdout: '', stderr: 'spawn failed' }); }
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, timeoutMs);
    child.stdout.on('data', d => (stdout += d.toString()));
    child.stderr.on('data', d => (stderr += d.toString()));
    child.on('error', () => { clearTimeout(timer); resolve({ code: -1, stdout, stderr: 'not executable' }); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}
const _binCache: Record<string, string | null> = {};
let _loginPath: string[] | null = null;
async function loginPathDirs(): Promise<string[]> {
  if (_loginPath) return _loginPath;
  try { const r = await run('bash', ['-lc', 'echo -n "$PATH"'], 5000); _loginPath = (r.code === 0 ? r.stdout : '').split(':').map(s => s.trim()).filter(Boolean); }
  catch { _loginPath = []; }
  return _loginPath;
}
/** Resolve a tool to an absolute path — tolerant of pm2's limited PATH (scans PATH, login-shell PATH and common install dirs). */
async function resolveBin(bin: string): Promise<string | null> {
  if (bin in _binCache) return _binCache[bin];
  let found: string | null = null;
  if (bin.startsWith('/')) { _binCache[bin] = fs.existsSync(bin) ? bin : null; return _binCache[bin]; }
  const home = process.env.HOME || '/root';
  const dirs = new Set<string>();
  (process.env.PATH || '').split(':').forEach(d => d && dirs.add(d));
  (await loginPathDirs()).forEach(d => dirs.add(d));
  ['/usr/local/bin', '/usr/bin', '/bin', '/snap/bin', '/usr/local/go/bin',
   home + '/go/bin', '/root/go/bin', '/home/ubuntu/go/bin', '/home/ec2-user/go/bin',
   home + '/.local/bin', home + '/.pdtm/go/bin', '/opt/' + bin, '/opt/' + bin + '/' + bin].forEach(d => dirs.add(d));
  for (const d of dirs) {
    const p = d.endsWith('/' + bin) ? d : d.replace(/\/$/, '') + '/' + bin;
    try { if (fs.existsSync(p) && fs.statSync(p).isFile()) { found = p; break; } } catch { /* */ }
  }
  _binCache[bin] = found;
  return found;
}
async function onPath(bin: string): Promise<boolean> { return (await resolveBin(bin)) !== null; }
const mapSev = (s: string): Finding['severity'] => {
  const x = (s || '').toLowerCase();
  if (x.startsWith('crit')) return 'Critical';
  if (x === 'high') return 'High';
  if (x === 'medium' || x === 'moderate') return 'Medium';
  if (x === 'low') return 'Low';
  return 'Info';
};

// ---- Nuclei (community templates; we invoke, we do not author exploits) ----
export const nucleiScanner: Scanner = {
  key: 'nuclei', kind: 'active',
  available: () => onPath(config.tools.nuclei),
  async run(ctx: ScanContext): Promise<Finding[]> {
    const args = ['-u', ctx.targetUrl, '-jsonl', '-silent', '-fr', '-severity', 'critical,high,medium,low'];
    const a = ctx.auth;
    if (a && a.method === 'bearer') args.push('-H', 'Authorization: Bearer ' + (a.secret || ''));
    else if (a && a.method === 'cookie') args.push('-H', 'Cookie: ' + (a.secret || ''));
    else if (a && a.method === 'header' && a.extra && a.extra.headerName) args.push('-H', a.extra.headerName + ': ' + (a.secret || ''));
    for (const eu of (ctx.extraUrls || []).slice(0, 50)) args.push('-u', eu);
    const r = await run((await resolveBin(config.tools.nuclei)) || config.tools.nuclei, args, 240000);
    const out: Finding[] = [];
    for (const line of r.stdout.split('\n').filter(Boolean)) {
      try {
        const j = JSON.parse(line);
        const info = j.info || {};
        out.push({
          title: info.name || j['template-id'] || 'Nuclei finding',
          severity: mapSev(info.severity),
          category: 'injection', scanner: 'nuclei',
          description: info.description, cwe: (info.classification && info.classification['cwe-id'] && String(info.classification['cwe-id'][0])) || undefined,
          evidence: { matchedAt: j['matched-at'], templateId: j['template-id'] },
        });
      } catch { /* skip malformed line */ }
    }
    return out;
  },
};

// ---- Nmap (service/port discovery) ----
export const nmapScanner: Scanner = {
  key: 'nmap', kind: 'active',
  available: () => onPath(config.tools.nmap),
  async run(ctx: ScanContext): Promise<Finding[]> {
    const r = await run((await resolveBin(config.tools.nmap)) || config.tools.nmap, ['-Pn', '-sV', '-oX', '-', ctx.host], 180000);
    const out: Finding[] = [];
    const re = /<port protocol="(\w+)" portid="(\d+)">\s*<state state="open"[^>]*\/>\s*(?:<service name="([^"]*)"(?:[^>]*product="([^"]*)")?)?/g;
    let m;
    while ((m = re.exec(r.stdout)) !== null) {
      const [, proto, port, svc, prod] = m;
      out.push({ title: `Open port ${port}/${proto}${svc ? ' (' + svc + ')' : ''}`, severity: 'Info', category: 'network', scanner: 'nmap',
        description: `Service exposed${prod ? ': ' + prod : ''}. Confirm it is intended to be internet-facing.`,
        remediation: 'Restrict exposure via firewall/security groups; disable unused services.', evidence: { port, proto, service: svc, product: prod } });
    }
    return out;
  },
};

// ---- OWASP ZAP baseline / full (report parsed from JSON) ----
function zapScanner(key: string, bin: () => string, timeout: number): Scanner {
  return {
    key, kind: 'active',
    available: () => onPath(bin()),
    async run(ctx: ScanContext): Promise<Finding[]> {
      // ZAP writes a JSON report to stdout-adjacent file; we request JSON on stdout via -J then read it back if produced.
      const r = await run((await resolveBin(bin())) || bin(), ['-t', ctx.targetUrl, '-J', 'zap-report.json', '-I'], timeout);
      const out: Finding[] = [];
      try {
        const fs = require('fs');
        if (fs.existsSync('zap-report.json')) {
          const rep = JSON.parse(fs.readFileSync('zap-report.json', 'utf8'));
          const alerts = (rep.site || []).flatMap((s: any) => s.alerts || []);
          for (const a of alerts) {
            const riskMap: any = { '3': 'High', '2': 'Medium', '1': 'Low', '0': 'Info' };
            out.push({ title: a.name || a.alert, severity: riskMap[a.riskcode] || 'Info', category: 'injection', scanner: key,
              description: (a.desc || '').replace(/<[^>]+>/g, ''), remediation: (a.solution || '').replace(/<[^>]+>/g, ''),
              cwe: a.cweid ? `CWE-${a.cweid}` : undefined, evidence: { instances: (a.instances || []).length } });
          }
        } else {
          out.push({ title: 'ZAP scan completed (no JSON report captured)', severity: 'Info', category: 'info', scanner: key,
            description: 'ZAP ran but no parseable report was found; check container volume mapping.', evidence: { exit: r.code } });
        }
      } catch (e: any) {
        out.push({ title: 'ZAP report parse error', severity: 'Info', category: 'info', scanner: key, evidence: { error: e.message } });
      }
      return out;
    },
  };
}
export const zapBaselineScanner = zapScanner('zap-baseline', () => config.tools.zapBaseline, 300000);
export const zapActiveScanner = zapScanner('zap-active', () => config.tools.zapFull, 600000);

// ---- testssl.sh (TLS deep audit) ----
export const testsslScanner: Scanner = {
  key: 'testssl', kind: 'active',
  available: () => onPath(config.tools.testssl),
  async run(ctx: ScanContext): Promise<Finding[]> {
    const r = await run((await resolveBin(config.tools.testssl)) || config.tools.testssl, ['--quiet', '--jsonfile', 'testssl.json', ctx.host], 240000);
    const out: Finding[] = [];
    try {
      const fs = require('fs');
      if (fs.existsSync('testssl.json')) {
        const arr = JSON.parse(fs.readFileSync('testssl.json', 'utf8'));
        for (const it of arr) {
          const sev = mapSev(it.severity);
          if (['Critical', 'High', 'Medium'].includes(sev)) {
            out.push({ title: `TLS: ${it.id}`, severity: sev, category: 'tls', scanner: 'testssl', description: it.finding, evidence: { id: it.id } });
          }
        }
      }
    } catch { /* ignore */ }
    if (out.length === 0) out.push({ title: 'testssl.sh audit completed', severity: 'Info', category: 'tls', scanner: 'testssl', evidence: { exit: r.code } });
    return out;
  },
};

export const activeScanners: Scanner[] = [nucleiScanner, nmapScanner, zapBaselineScanner, zapActiveScanner, testsslScanner];
