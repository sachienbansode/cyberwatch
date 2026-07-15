\connect cyberwatch
INSERT INTO identity.tenants(id,name,re_category)
VALUES ('00000000-0000-0000-0000-000000000001','Treeants Technologies','Qualified')
ON CONFLICT (id) DO NOTHING;

INSERT INTO vapt.scanners(key,name,kind,tool,enabled) VALUES
 ('passive','Built-in passive analyser','passive',NULL,true),
 ('zap-baseline','OWASP ZAP baseline','active','zap-baseline.py',true),
 ('zap-active','OWASP ZAP full active scan','active','zap-full-scan.py',true),
 ('nuclei','Nuclei template scanner','active','nuclei',true),
 ('nmap','Nmap service/port scan','active','nmap',true),
 ('testssl','testssl.sh TLS audit','active','testssl.sh',true)
ON CONFLICT (key) DO NOTHING;
