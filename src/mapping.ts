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

export function enrich(f: Finding): Finding {
  if (!f.frameworkRefs || f.frameworkRefs.length === 0) {
    f.frameworkRefs = CATEGORY_REFS[f.category] || ['SEBI: DE.VA', 'RBI: Sec 26 (VA/PT)'];
  }
  return f;
}
