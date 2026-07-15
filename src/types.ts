export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type Profile = 'passive' | 'baseline' | 'active';

export interface Finding {
  title: string;
  description?: string;
  remediation?: string;
  severity: Severity;
  cvss?: number;
  cwe?: string;
  category: string;                 // tls | headers | cookies | exposure | injection | network | dependency | info
  scanner: string;
  evidence?: Record<string, any>;
  frameworkRefs?: string[];         // filled by mapping if omitted
  cve?: string;
  cvssVector?: string;
  refs?: string[];
  source?: string;                  // scanner | import:<tool> | manual
}

export interface AuthConfig { method: string; loginUrl?: string; username?: string; secret?: string; extra?: any; }
export interface ScanContext {
  jobId: string;
  tenantId: string;
  assetId: string;
  targetUrl: string;
  host: string;
  profile: Profile;
  auth?: AuthConfig;
  extraUrls?: string[];
}

export interface Scanner {
  key: string;
  kind: 'passive' | 'active';
  /** Return true if this scanner can run (e.g. external tool present on PATH). */
  available(): Promise<boolean>;
  run(ctx: ScanContext): Promise<Finding[]>;
}
