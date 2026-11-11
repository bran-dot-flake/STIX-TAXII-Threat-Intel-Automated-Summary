/* Optional development acceptance runner: npm install playwright@1.62.1.
 * No browser package or service is required by the deployed static website.
 */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = (process.argv[2] || 'http://127.0.0.1:4173').replace(/\/$/, '');
const output = process.argv[3];

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.BROWSER_EXECUTABLE ? { executablePath: process.env.BROWSER_EXECUTABLE } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
    await page.goto(base);
    await page.getByRole('heading', { name: 'Daily Brief', exact: true }).waitFor();
    const snapshot = await (await page.request.get(base + '/snapshot.json')).json();
    assert.equal(await page.locator('.sidebar').count(), 0);
    assert.equal(await page.locator('.brief-findings .finding').count(), Math.min(3, new Set((snapshot.reports[0]?.items || []).map(r => r.kind + '|' + r.value)).size));
    const actual = await page.locator('.metric strong').allTextContents();
    assert.equal(Number(actual[1].replaceAll(',', '')), new Set(snapshot.records.filter(r => r.kind !== 'vulnerability').map(r => r.kind + '|' + r.value)).size);
    assert.equal(Number(actual[3]), snapshot.reports.length);
    await page.getByRole('button', { name: '7D', exact: true }).click();
    assert.equal(await page.locator('.bar').count(), 7);
    await page.getByRole('button', { name: '30D', exact: true }).click();
    assert.equal(await page.locator('.bar').count(), 30);
    assert(await page.locator('.story img').count() <= 1);
    await page.getByRole('link', { name: 'Vulnerabilities', exact: true }).click();
    await page.locator('#vulnerabilities[open]').waitFor();
    const cve = snapshot.records.find(r => r.source === 'cisa-kev');
    if (cve) {
      await page.locator('#cve-search').fill(cve.value);
      assert.equal(await page.locator('#cve-results tbody tr').count(), 1);
      await page.locator('#cve-results [data-evidence]').first().click();
      await page.locator('dialog[open]').waitFor();
      await page.keyboard.press('Escape');
      await page.locator('#cve-search').fill('');
    }
    await page.getByRole('link', { name: 'Archive', exact: true }).click();
    await page.locator('#archive[open]').waitFor();
    if (snapshot.reports.length) {
      await page.locator('#archive-select').selectOption(snapshot.reports.at(-1).id);
      assert.equal(await page.locator('#archived-report .evidence').count(), snapshot.reports.at(-1).items.length);
    }
    if (snapshot.stix?.objects.length) {
      await page.locator('#context > summary').click();
      const item = snapshot.stix.objects.find(o => snapshot.stix.relationships.some(r => r.source_ref === o.id || r.target_ref === o.id));
      if (item) {
        await page.locator('#catalog-search').fill(item.external_id);
        await page.locator('#catalog-results [data-stix]').first().click();
        await page.locator('dialog[open]').waitFor();
        assert(await page.locator('.relationship-list li').count() > 0);
        await page.keyboard.press('Escape');
        await page.locator('#catalog-search').fill('');
      }
    }
    const query = cve?.value || snapshot.news[0]?.title.split(' ')[0];
    if (query) {
      await page.locator('#global-search').fill(query);
      await page.locator('#global-search').press('Enter');
      await page.locator('#search-results:not([hidden])').waitFor();
      assert(await page.locator('#search-results li').count() > 0);
      await page.getByRole('button', { name: 'Clear search' }).click();
    }
    for (const width of [390, 768, 1440]) {
      await page.setViewportSize({ width, height: width === 390 ? 900 : 1050 });
      for (const id of ['context', 'archive', 'vulnerabilities']) {
        await page.locator('#' + id).evaluate(el => { el.open = false; });
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'Horizontal overflow at ' + width);
      if (output && [390, 1440].includes(width)) {
        fs.mkdirSync(output, { recursive: true });
        await page.screenshot({ path: path.join(output, width === 390 ? 'dashboard-mobile.png' : 'dashboard-desktop.png'), fullPage: true });
      }
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ status: 'passed', widths: [390, 768, 1440], metrics: actual, stixObjects: snapshot.stix?.objects.length || 0, relationships: snapshot.stix?.relationships.length || 0, errors }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
