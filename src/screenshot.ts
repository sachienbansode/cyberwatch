// Optional screenshot capture. Uses Playwright if installed:
//   npm i playwright && npx playwright install chromium
// Degrades gracefully (returns null) when Playwright/chromium are absent.
export async function captureScreenshot(url: string): Promise<string | null> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { chromium } = require('playwright');
    const browser = await chromium.launch({ args: ['--no-sandbox'] });
    try {
      const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      await page.goto(url, { timeout: 20000, waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(1200);
      const buf: Buffer = await page.screenshot({ type: 'png', fullPage: false });
      return buf.toString('base64');
    } finally { await browser.close(); }
  } catch {
    return null; // Playwright not installed or navigation failed
  }
}

// Capture screenshots of several URLs in one browser session. Returns { url: base64 }.
export async function captureMany(urls: string[]): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  try {
    const { chromium } = require('playwright');
    const browser = await chromium.launch({ args: ['--no-sandbox'] });
    try {
      for (const u of urls.slice(0, 8)) {
        try {
          const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
          await page.goto(u, { timeout: 18000, waitUntil: 'domcontentloaded' });
          await page.waitForTimeout(900);
          const buf: Buffer = await page.screenshot({ type: 'png', fullPage: false });
          out[u] = buf.toString('base64');
          await page.close();
        } catch { /* skip this url */ }
      }
    } finally { await browser.close(); }
  } catch { /* playwright absent */ }
  return out;
}
