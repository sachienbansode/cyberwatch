import { Severity, Finding } from './types';

// Days-to-remediate SLA (SEBI CSCRF): high-severity patch 1 week, others 3 months.
export function slaDays(sev: Severity): number {
  return sev === 'Critical' || sev === 'High' ? 7 : 90;
}

// Default regulatory linkage per finding category (RBI IT Gov MD 2023 / SEBI CSCRF).
const CATEGORY_REFS: Record<string, string[]> = {
  tls:        ['RBI: Sec 16 (Cryptographic controls)', 'SEBI: PR.DS'],
  headers:    ['RBI: DPSC 2021 (App controls)', 'SEBI: PR.AS'],
  cookies:    ['SEBI: PR.DS', 'RBI: Sec 19 (Access controls)'],
  exposure:   ['SEBI: ID.AM', 'RBI: Sec 9 (Asset management)'],
  injection:  ['SEBI: PR.AS', 'RBI: Sec 12 (Secure development)'],
  dependency: ['SEBI: GV.SC.S5 (SBOM)', 'RBI: Sec 13 (Patch mgmt)'],
  network:    ['SEBI: PR.NS', 'RBI: Sec 18/19'],
  info:       ['SEBI: ID.AM'],
};

const IMPACT: Record<string, string> = {
  tls: 'Traffic to this service could be intercepted, downgraded or tampered with, exposing credentials and session data in transit.',
  headers: 'Missing browser security headers leave users exposed to cross-site scripting (XSS), clickjacking and MIME-sniffing attacks.',
  cookies: 'Session cookies without protective flags can be stolen or leaked, enabling session hijacking and account takeover.',
  exposure: 'Disclosed files, versions or metadata reveal information that helps an attacker fingerprint and target the system.',
  injection: 'An attacker could inject malicious input to read or modify data, run scripts in users\' browsers, or bypass access controls.',
  dependency: 'A known-vulnerable component may be exploited, potentially leading to remote code execution or data compromise.',
  network: 'Each internet-exposed service widens the attack surface and may be brute-forced, fingerprinted or exploited.',
  vulnerability: 'If exploited, this weakness could let an attacker compromise the confidentiality, integrity or availability of the application.',
  info: 'Informational finding — provides useful context with low direct risk.',
};
export function enrich(f: Finding): Finding {
  if (!f.frameworkRefs || f.frameworkRefs.length === 0) {
    f.frameworkRefs = CATEGORY_REFS[f.category] || ['SEBI: DE.VA', 'RBI: Sec 26 (VA/PT)'];
  }
  if (!f.impact) f.impact = IMPACT[f.category] || IMPACT.vulnerability;
  return f;
}
