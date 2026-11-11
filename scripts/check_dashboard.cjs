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
    const analytics=await import('../website/analytics.js');
    const expectedStories=analytics.additionalStories(snapshot.news,snapshot.exported_at,snapshot.editions?.[0]);
    assert.equal(await page.locator('.sidebar').count(), 0);
    assert.equal(await page.locator('[data-news-filter],.news-filters').count(),0);
    if(snapshot.editions?.length){
      const edition=snapshot.editions[0];
      assert.equal(await page.locator('.radar article').count(),edition.topics.length>1?Math.min(3,edition.topics.length-1):edition.topics.length);
      assert.deepEqual(await page.locator('.editorial-lead .brief-overview').allTextContents(),edition.plan.overview.map(p=>p.map(c=>c.text).join(' ')));
      for(const topic of edition.topics)assert((await page.locator('#brief').innerText()).includes(topic.headline));
      const supporting=page.locator('#brief > .supporting-evidence');
      const groups=analytics.evidenceGroups(analytics.editionEvidence(edition),edition.topics);
      assert.equal(await supporting.count(),groups.length?1:0);
      if(groups.length){
        await supporting.locator(':scope > summary').click();
        assert.equal(await supporting.locator('.brief-overview,.report-overview,.report-topic').count(),0);
        assert.equal(await supporting.locator('.evidence-group').count(),groups.length);
        assert.equal(await supporting.locator('.evidence').count(),groups.reduce((n,g)=>n+g.records.length,0));
        const first=supporting.locator('.evidence-group').first();
        await first.locator(':scope > summary').click();
        assert.equal(await first.locator('.record-detail:visible').count(),0);
        await first.locator('.evidence > summary').first().click();
        assert.equal(await first.locator('.record-detail:visible').count(),1);
        const original=groups[0].records[0];
        const source=first.locator('.record-detail a').first();
        assert.equal(await source.getAttribute('href'),original.source_url);
        if(analytics.isRawSource(original.source_url))assert((await source.innerText()).includes('Raw source data'));
        await first.locator('.evidence > summary').first().click();
        if(groups.length>1){await supporting.locator('.evidence-group > summary').nth(1).click();assert(await first.getAttribute('open')!==null);}
        await supporting.locator('.evidence-group').evaluateAll(nodes=>nodes.forEach(n=>n.open=false));
        await supporting.locator(':scope > summary').click();
      }
      for(const href of await page.locator('.editorial-lead a,.radar a').evaluateAll(nodes=>nodes.map(n=>n.href)))assert(!analytics.isRawSource(href),'Reader link opens raw data');
      const detail=page.locator('.radar [data-evidence]').first();
      if(await detail.count()){
        const id=await detail.getAttribute('data-evidence');
        await detail.click();await page.locator('dialog[open]').waitFor();
        const row=analytics.editionEvidence(edition).find(r=>r.id===id);
        assert((await page.locator('#dialog-content').innerText()).includes(row.value));
        assert((await page.locator('#dialog-content a').last().innerText()).includes('Raw source data'));
        await page.keyboard.press('Escape');
      }

    }else assert.equal(await page.locator('.brief-findings .finding').count(),(await import('../website/analytics.js')).briefDigest(snapshot.reports[0]).length);
    const actual = await page.locator('.metric strong').allTextContents();
    assert.equal(Number(actual[1].replaceAll(',', '')), new Set(snapshot.records.filter(r => r.kind !== 'vulnerability').map(r => r.kind + '|' + r.value)).size);
    assert.equal(Number(actual[3]), snapshot.reports.length+(snapshot.editions||[]).length);
    await page.getByRole('button', { name: '7D', exact: true }).click();
    assert.equal(await page.locator('.bar').count(), 7);
    await page.getByRole('button', { name: '30D', exact: true }).click();
    assert.equal(await page.locator('.bar').count(), 30);
    assert.equal(await page.locator('.story-featured').count(),expectedStories.length?1:0);
    assert.deepEqual(await page.locator('.story').evaluateAll(nodes=>nodes.map(n=>n.dataset.storyId)),expectedStories.slice(0,6).map(r=>r.id));
    assert(!(await page.locator('#intelligence').innerText()).includes('Source excerpt'));
    if(snapshot.editions?.[0]?.input.news.some(r=>r.source_url.includes('/2026/11/10/'))){
      assert.equal(await page.locator('.editorial-lead a').first().getAttribute('href'),snapshot.editions[0].input.news.find(r=>r.source_url.includes('/2026/11/10/')).source_url);
    }
    assert(await page.locator('.story img').count() <= 1);
    assert.deepEqual(await page.locator('main > section[id], main > details[id]').evaluateAll(nodes=>nodes.map(n=>n.id).filter(id=>id!=='search-results')),['brief','intelligence','trends','context','vulnerabilities','archive']);
    if(!snapshot.editions?.length&&snapshot.reports[0]?.narrative){
      const topics=snapshot.reports[0].narrative.plan.topics;
      for(const topic of topics)assert((await page.locator('#brief').innerText()).includes(topic.headline));
      assert(!(await page.locator('#brief').innerText()).includes('source observations for review'));
    }
    const excerpt=page.locator('.story-excerpt').first();
    if(await excerpt.count()){
      await excerpt.locator('summary').click();
      assert(await excerpt.getAttribute('open')!==null);
      await excerpt.locator('summary').click();
    }
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
      assert.equal(await page.locator('#archived-report .evidence').count(), (snapshot.reports.at(-1).observations||snapshot.reports.at(-1).items).length);
      const groupedReport=snapshot.reports.find(r=>analytics.briefDigest(r).some(t=>t.records.length>1&&t.records[0]?.kind!=='vulnerability'));
      if(groupedReport)await page.locator('#archive-select').selectOption(groupedReport.id);
      const legacySupport=page.locator('#archived-report [data-supporting]').first();
      if(await legacySupport.count()){
        await legacySupport.click();
        assert(await legacySupport.locator('xpath=ancestor::article[1]').locator('.topic-evidence').getAttribute('open')!==null);
        assert.equal(await page.locator('#brief > .supporting-evidence[open]').count(),0);
      }

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
    await page.locator('#global-search').blur();
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
    // Isolated presentation fixtures: source validation is exercised by Python.
    // Route overrides never modify the server, source data, or published edition.
    if(snapshot.reports.length){
      const legacy=structuredClone(snapshot);legacy.synthetic=true;legacy.editions=[];
      await page.route('**/snapshot.json',route=>route.fulfill({json:legacy}));
      await page.goto(base);await page.getByRole('heading',{name:'Daily Brief',exact:true}).waitFor();
      const supporting=page.locator('#brief > .supporting-evidence');
      await supporting.locator(':scope > summary').click();
      assert.equal(await supporting.locator('.evidence').count(),(legacy.reports[0].observations||legacy.reports[0].items).length);
      assert.equal(await supporting.locator('.brief-overview,.report-overview').count(),0);
      await page.unroute('**/snapshot.json');
    }
    if(snapshot.editions?.length){
      const quiet=structuredClone(snapshot);quiet.synthetic=true;
      quiet.editions[0].topics=[];quiet.editions[0].input={records:[],news:[],updates:[],context:[]};
      quiet.editions[0].plan={overview:[[{fact_ids:['quiet'],text:'No source-dated developments in the available feeds.'}]],topics:[]};
      quiet.news=[];
      await page.route('**/snapshot.json',route=>route.fulfill({json:quiet}));
      await page.goto(base);await page.getByRole('heading',{name:'Daily Brief',exact:true}).waitFor();
      assert.equal(await page.locator('.radar,.supporting-evidence,.story').count(),0);
      const placeholders=structuredClone(snapshot);placeholders.synthetic=true;
      placeholders.news=expectedStories.slice(0,3).map((r,i)=>({...r,excerpt:i===0?'':i===1?'Source excerpt':'A short supported source observation.'}));
      await page.unroute('**/snapshot.json');
      await page.route('**/snapshot.json',route=>route.fulfill({json:placeholders}));
      await page.goto(base);await page.getByRole('heading',{name:'Daily Brief',exact:true}).waitFor();
      assert(!(await page.locator('#intelligence').innerText()).includes('Source excerpt'));
      assert.equal(await page.locator('.story-excerpt').count(),placeholders.news.length>2?1:0);
      await page.unroute('**/snapshot.json');
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ status: 'passed', widths: [390, 768, 1440], metrics: actual, stixObjects: snapshot.stix?.objects.length || 0, relationships: snapshot.stix?.relationships.length || 0, errors }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
