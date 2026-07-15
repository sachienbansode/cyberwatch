-- Finding implication/impact + backfill
\connect cyberwatch
ALTER TABLE vapt.findings ADD COLUMN IF NOT EXISTS impact text;
UPDATE vapt.findings SET impact = CASE category
  WHEN 'tls' THEN 'Traffic to this service could be intercepted, downgraded or tampered with, exposing credentials and session data in transit.'
  WHEN 'headers' THEN 'Missing browser security headers leave users exposed to cross-site scripting (XSS), clickjacking and MIME-sniffing attacks.'
  WHEN 'cookies' THEN 'Session cookies without protective flags can be stolen or leaked, enabling session hijacking and account takeover.'
  WHEN 'exposure' THEN 'Disclosed files, versions or metadata reveal information that helps an attacker fingerprint and target the system.'
  WHEN 'injection' THEN 'An attacker could inject malicious input to read or modify data, run scripts in users'' browsers, or bypass access controls.'
  WHEN 'dependency' THEN 'A known-vulnerable component may be exploited, potentially leading to remote code execution or data compromise.'
  WHEN 'network' THEN 'Each internet-exposed service widens the attack surface and may be brute-forced, fingerprinted or exploited.'
  WHEN 'info' THEN 'Informational finding — provides useful context with low direct risk.'
  ELSE 'If exploited, this weakness could let an attacker compromise the confidentiality, integrity or availability of the application.'
END WHERE impact IS NULL;
