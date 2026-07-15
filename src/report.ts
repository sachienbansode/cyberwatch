import PDFDocument from 'pdfkit';
import { Response } from 'express';
import * as path from 'path';
import * as fs from 'fs';
import { query } from './db';

const NAVY = '#233b57', BRAND = '#e07f10', MUTED = '#6b7789';
const sevColor: Record<string, string> = { Critical: '#c0392b', High: '#e07f10', Medium: '#b8860b', Low: '#1E9E73', Info: '#8592A0' };
function pngSize(buf: Buffer): { w: number; h: number } { try { return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) }; } catch { return { w: 1280, h: 800 }; } }

export async function streamReport(jobId: string, tenant: string, res: Response) {
  const [job] = await query<any>('SELECT * FROM vapt.scan_jobs WHERE id=$1 AND tenant_id=$2', [jobId, tenant]);
  if (!job) { res.status(404).json({ error: 'scan not found' }); return; }
  const [asset] = await query<any>('SELECT * FROM asset.assets WHERE id=$1', [job.asset_id]);
  const findings = await query<any>(
    `SELECT * FROM vapt.findings WHERE scan_job_id=$1
       ORDER BY (CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END)`, [jobId]);

  const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  findings.forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
  const allShots = await query<any>('SELECT caption, image_b64, kind FROM vapt.screenshots WHERE scan_job_id=$1', [jobId]);
  const shotMap: Record<string, string> = {};
  allShots.forEach(s => { if (s.caption) shotMap[s.caption] = s.image_b64; });
  const shot = allShots.find(s => s.kind === 'asset') || allShots[0];

  const doc = new PDFDocument({ size: 'A4', margin: 54, bufferPages: true, info: { Title: `AntShield VAPT Report ${asset?.name || ''} v${job.version}` } });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="AntShield_VAPT_${(asset?.name||'scan').replace(/\W+/g,'_')}_v${job.version}.pdf"`);
  doc.pipe(res);

  const logo = path.join(__dirname, '..', 'assets', 'logo.png');
  if (fs.existsSync(logo)) { try { doc.image(logo, 54, 48, { width: 40 }); } catch {} }
  doc.fillColor(NAVY).fontSize(22).font('Helvetica-Bold').text('AntShield', 104, 52);
  doc.fillColor(MUTED).fontSize(11).font('Helvetica').text('VAPT Assessment Report', 104, 78);
  doc.moveTo(54, 104).lineTo(541, 104).strokeColor('#e5e9ef').stroke();

  doc.moveDown(2);
  doc.fillColor(NAVY).fontSize(17).font('Helvetica-Bold').text(asset?.name || job.target_url);
  doc.fillColor(MUTED).fontSize(10).font('Helvetica');
  doc.text(`Target: ${job.target_url}`);
  doc.text(`Scan version: v${job.version}   •   Profile: ${job.profile}   •   Scanners: ${(job.scanners||[]).join(', ') || '—'}`);
  doc.text(`Started: ${job.started_at ? new Date(job.started_at).toLocaleString() : '—'}    Completed: ${job.finished_at ? new Date(job.finished_at).toLocaleString() : '—'}`);
  doc.text(`Report generated: ${new Date().toLocaleString()}   •   Confidential`);

  // Summary band
  doc.moveDown(1.2);
  doc.fillColor(NAVY).fontSize(13).font('Helvetica-Bold').text('Executive summary');
  doc.moveDown(0.4);
  const total = findings.length;
  doc.fillColor('#333').fontSize(10).font('Helvetica')
    .text(`This ${job.profile} assessment of ${asset?.name || job.target_url} identified ${total} finding${total===1?'':'s'}: `
      + `${counts.Critical} critical, ${counts.High} high, ${counts.Medium} medium, ${counts.Low} low, ${counts.Info} informational. `
      + `Findings are mapped to RBI (IT Governance MD 2023) and SEBI (CSCRF) obligations, with remediation SLAs of one week for high-severity and three months for the rest.`);

  // Severity table
  doc.moveDown(0.8);
  let x = 54, y = doc.y;
  ['Critical','High','Medium','Low','Info'].forEach(s => {
    doc.roundedRect(x, y, 92, 42, 6).fill(sevColor[s]);
    doc.fillColor('#fff').fontSize(18).font('Helvetica-Bold').text(String(counts[s]), x, y+6, { width: 92, align: 'center' });
    doc.fontSize(8).font('Helvetica').text(s.toUpperCase(), x, y+30, { width: 92, align: 'center' });
    x += 97;
  });
  doc.y = y + 60; doc.x = 54;

  // Target screenshot (evidence)
  if (shot && shot.image_b64) {
    try {
      const buf = Buffer.from(shot.image_b64, 'base64');
      const { w, h } = pngSize(buf); const iw = 487; const ih = Math.min(300, Math.round(iw * h / (w || 1)));
      if (doc.y + ih + 46 > 792) doc.addPage();
      doc.moveDown(0.6);
      doc.fillColor(NAVY).fontSize(12).font('Helvetica-Bold').text('Target screenshot');
      doc.moveDown(0.3);
      const iy = doc.y;
      doc.image(buf, 54, iy, { fit: [iw, 300] });
      doc.y = iy + ih + 12; doc.x = 54;
    } catch { /* image best-effort */ }
  }

  // Findings detail
  doc.moveDown(1);
  doc.fillColor(NAVY).fontSize(13).font('Helvetica-Bold').text('Findings & recommendations');
  doc.moveDown(0.5);
  if (!findings.length) doc.fillColor(MUTED).fontSize(10).font('Helvetica').text('No findings recorded for this scan.');
  findings.forEach((f, i) => {
    if (doc.y > 720) doc.addPage();
    const yy = doc.y;
    doc.roundedRect(54, yy, 60, 16, 4).fill(sevColor[f.severity] || MUTED);
    doc.fillColor('#fff').fontSize(8).font('Helvetica-Bold').text(f.severity.toUpperCase(), 54, yy+4, { width: 60, align: 'center' });
    doc.fillColor(NAVY).fontSize(11).font('Helvetica-Bold').text(`${i+1}. ${f.title}`, 122, yy);
    doc.fillColor(MUTED).fontSize(9).font('Helvetica').text(`${f.category || '-'}${f.cvss ? '  •  CVSS '+f.cvss : ''}${f.cve ? '  •  '+f.cve : ''}${f.risk_score != null ? '  •  Risk '+f.risk_score : ''}${f.kev ? '  •  KEV' : ''}${f.cwe ? '  •  '+f.cwe : ''}  •  ${(f.framework_refs||[]).join('  •  ')}`, 122);
    if (f.evidence && f.evidence.url) doc.fillColor('#2E6FE0').fontSize(8.5).font('Helvetica').text('Location: ' + String(f.evidence.url).slice(0, 155), 122, undefined, { width: 419 });
    if (f.description) doc.fillColor('#333').fontSize(9.5).font('Helvetica').text(f.description, 122, undefined, { width: 419 });
    if (f.impact) doc.fillColor('#8a4b00').fontSize(8.8).font('Helvetica-Oblique').text('Implication: ' + f.impact, 122, undefined, { width: 419 });
    if (f.remediation) { doc.fillColor(BRAND).fontSize(9).font('Helvetica-Bold').text('Recommendation: ', 122, undefined, { continued: true }); doc.fillColor('#333').font('Helvetica').text(f.remediation, { width: 419 }); }
    const evd: any = (f.evidence && typeof f.evidence === 'object') ? f.evidence : {};
    if (evd.request || evd.response) {
      doc.moveDown(0.15); doc.fillColor('#555').fontSize(8.5).font('Helvetica-Bold').text('Evidence', 122, undefined, { width: 419 });
      if (evd.request) doc.font('Courier').fontSize(8).fillColor('#444').text('> ' + String(evd.request).slice(0, 160), 122, undefined, { width: 419 });
      if (evd.response) doc.font('Courier').fontSize(8).fillColor('#444').text('< ' + String(evd.response).slice(0, 300), 122, undefined, { width: 419 });
    } else {
      const ev = Object.entries(evd).filter(([, v]) => v != null && v !== '').map(([k, v]) => `${k}: ${String(v).slice(0, 120)}`).join('   -   ');
      if (ev) doc.fillColor('#555').fontSize(8.5).font('Helvetica-Oblique').text('Evidence: ' + ev, 122, undefined, { width: 419 });
    }
    const furl = evd.url;
    if (furl && furl !== job.target_url && shotMap[furl]) {
      try {
        const fbuf = Buffer.from(shotMap[furl], 'base64'); const ps = pngSize(fbuf); const fiw = 300; const fih = Math.min(190, Math.round(fiw * ps.h / (ps.w || 1)));
        if (doc.y + fih + 22 > 792) doc.addPage();
        doc.moveDown(0.3); const fy = doc.y; doc.image(fbuf, 122, fy, { fit: [fiw, 190] }); doc.y = fy + fih + 5; doc.x = 54;
        doc.fillColor(MUTED).fontSize(7.5).font('Helvetica-Oblique').text('Screenshot evidence: ' + furl, 122, undefined, { width: 419 });
      } catch { /* */ }
    }
    doc.moveDown(0.8);
    doc.moveTo(54, doc.y).lineTo(541, doc.y).strokeColor('#eef2f7').stroke();
    doc.moveDown(0.4);
  });

  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    const y = doc.page.height - 38;
    doc.fontSize(8).fillColor(MUTED).font('Helvetica').text('AntShield · Treeants Technologies · Confidential — for the named recipient only. Not legal advice.', 54, y, { width: doc.page.width - 108, align: 'center', lineBreak: false });
    doc.fontSize(8).fillColor(MUTED).text(String(i + 1 - range.start) + ' / ' + range.count, doc.page.width - 90, y, { width: 40, align: 'right', lineBreak: false });
  }
  doc.flushPages();
  doc.end();
}
