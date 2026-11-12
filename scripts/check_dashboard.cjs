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
    await page.getByRole('heading', { name: 'Weekly Brief', exact: true }).waitFor();
    const snapshot = await (await page.request.get(base + '/snapshot.json')).json();
    const analytics=await import('../website/analytics.js');
    const selected=analytics.publicationView(snapshot).primary;
    const expectedStories=analytics.additionalStories(snapshot.news,snapshot.exported_at,analytics.featuredPublication(snapshot));
    assert.equal(await page.locator('.sidebar').count(), 0);
    assert.equal(await page.locator('[data-news-filter],.news-filters').count(),0);
    if(selected){
      const edition=selected;
      assert.equal(await page.locator('.radar article').count(),edition.version===3?edition.topics.length:Math.min(3,Math.max(0,edition.topics.length-1)));
      assert.deepEqual(await page.locator('.editorial-lead .brief-overview').allTextContents(),edition.plan.overview.map(p=>p.map(c=>c.text).join(' ')));
      assert.equal(await page.locator('.edition-date').innerText(),analytics.weeklyPeriod(edition.window_start,edition.window_end));
      assert.equal(await page.locator('#brief .collection-status,#brief .lead-development,#brief .lead-source').count(),0);
      assert(!(await page.locator('#brief').innerText()).includes('Sources checked'));
      for(const words of await page.locator('.radar article p').allTextContents())assert(words.split(/\s+/).length<=38);
      if(edition.version===3)assert.deepEqual(await page.locator('.radar article p').allTextContents(),edition.topics.map(t=>edition.plan.topics.find(r=>r.topic_id===t.id).summary.text));
      await page.evaluate(()=>document.fonts.ready);
      assert((await page.locator('.editorial-lead h1').evaluate(n=>getComputedStyle(n).fontFamily)).includes('EMBER Newsreader'));
      const art=snapshot.illustrations?.find(a=>a.edition_id===edition.id);
      if(art){const picture=page.locator('.editorial-lead img');assert.equal(await picture.getAttribute('alt'),art.alt);await picture.evaluate(n=>n.decode());assert(await picture.evaluate(n=>n.complete&&n.naturalWidth>0));const ratio=await picture.evaluate(n=>n.getBoundingClientRect().width/n.closest('.lead-body').getBoundingClientRect().width);assert(ratio>=.25&&ratio<=.35);}

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

    }else assert.equal(await page.locator('.editorial-lead').count(),0);
    const actual = await page.locator('.metric strong').allTextContents();
    assert.equal(Number(actual[1].replaceAll(',', '')), new Set(snapshot.records.filter(r => r.kind !== 'vulnerability').map(r => r.kind + '|' + r.value)).size);
    assert.equal(Number(actual[3]), analytics.visibleHistory(snapshot).length);
    await page.getByRole('button', { name: '7D', exact: true }).click();
    assert.equal(await page.locator('#trend .bar').count(), 7);
    await page.getByRole('button', { name: '30D', exact: true }).click();
    assert.equal(await page.locator('#trend .bar').count(), 30);
    assert.equal(await page.locator('#reporting-trend,.reporting-trend,.reporting-data').count(),0);
    const series=analytics.dailyKev(snapshot.records,30,new Date().toISOString());
    assert.equal(await page.locator('.chart-data,#chart-table,#show-all-days').count(),0);
    assert.equal(await page.locator('#last-updated,.last-updated').count(),0);
    assert(!(await page.locator('header').innerText()).includes('Updated'));
    assert.deepEqual(await page.locator('#trend .bar').evaluateAll(nodes=>nodes.map(n=>n.getAttribute('aria-label'))),series.map(r=>`${r.date}: ${r.count} catalog additions`));
    assert.equal(await page.locator('.bar-chart').getAttribute('aria-describedby'),'trend-description');
    assert((await page.locator('#trend-description').textContent()).includes(`${series.reduce((n,r)=>n+r.count,0)} KEV catalog additions`));
    assert((await page.locator('#trend-description').getAttribute('class')).includes('sr-only'));
    assert.equal(await page.locator('footer a,footer button').count(),2);
    assert.equal((await page.locator('footer').innerText()).trim().replace(/\s+/g,' '),'GitHub ↗ Sources & Licenses');
    await page.getByRole('button',{name:'Sources & Licenses',exact:true}).click();
    await page.locator('#sources-dialog[open]').waitFor();
    assert((await page.locator('#sources-dialog').innerText()).includes('SANS Technology Institute, Internet Storm Center'));
    assert((await page.locator('#sources-dialog').innerText()).includes('shared under CC BY-NC-SA 4.0'));
    const license=await (await page.request.get(base+'/assets/licenses/MITRE-ATTACK.txt')).text();
    assert.equal((await page.locator('.license-text').textContent()).trim(),license.replaceAll('\r\n','\n').trim());
    for(const article of snapshot.news.filter(r=>r.source==='sans-isc'))assert(await page.locator('#sans-credits a').evaluateAll((nodes,url)=>nodes.some(n=>n.href===url),article.source_url));
    await page.keyboard.press('Shift+Tab');
    assert(await page.locator('#sources-dialog').evaluate(n=>n.contains(document.activeElement)));
    await page.keyboard.press('Escape');
    assert(await page.getByRole('button',{name:'Sources & Licenses',exact:true}).evaluate(n=>n===document.activeElement));
    assert.equal(await page.locator('.story-featured').count(),expectedStories.length?1:0);
    assert.deepEqual(await page.locator('.story').evaluateAll(nodes=>nodes.map(n=>n.dataset.storyId)),expectedStories.slice(0,6).map(r=>r.id));
    assert(!(await page.locator('#intelligence').innerText()).includes('Source excerpt'));
    assert(await page.locator('.story img').count() <= 1);
    assert.deepEqual(await page.locator('main > section[id], main > details[id]').evaluateAll(nodes=>nodes.map(n=>n.id).filter(id=>id!=='search-results')),['brief','intelligence','trends','context','vulnerabilities','archive']);
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
    const previous=analytics.visibleHistory(snapshot);
    assert.equal(await page.locator('#archive-select option').count(),previous.length);
    if(previous.length){await page.locator('#archive-select').selectOption(previous.at(-1).id);assert((await page.locator('#archived-report').innerText()).includes(previous.at(-1).headline||previous.at(-1).topics[0].headline));}
    else assert((await page.locator('#archive').innerText()).includes('No previous weekly editions.'));
    if (snapshot.stix?.objects.length) {
      await page.locator('#context > summary').click();
      const item = snapshot.stix.objects.find(o => snapshot.stix.relationships.some(r => r.source_ref === o.id || r.target_ref === o.id));
      if (item) {
        await page.locator('#catalog-search').fill(item.external_id);
        await page.locator('#catalog-results [data-stix]').first().click();
        await page.locator('dialog[open]').waitFor();
        assert(await page.locator('.relationship-list li').count() > 0);
        assert((await page.locator('.relationship-list small').first().innerText()).includes('Relationship modified:'));
        await page.locator('#dialog-title').click();assert.equal(await page.locator('#detail-dialog[open]').count(),1);
        await page.mouse.click(4,4);assert.equal(await page.locator('#detail-dialog[open]').count(),0);
        await page.locator('#catalog-results [data-stix]').first().click();await page.locator('#detail-dialog[open]').waitFor();

        await page.keyboard.press('Escape');
        await page.locator('#catalog-search').fill('');
      }
      const sparse=snapshot.stix.objects.find(o=>!snapshot.stix.relationships.some(r=>r.source_ref===o.id||r.target_ref===o.id));
      if(sparse){
        await page.locator('#catalog-search').fill(sparse.external_id);
        await page.locator('#catalog-results [data-stix]').first().click();
        await page.locator('dialog[open]').waitFor();
        assert.equal(await page.locator('#dialog-title').innerText(),sparse.name);
        assert.equal(await page.getByRole('heading',{name:'Source relationships',exact:true}).count(),0);
        assert.equal(await page.locator('#dialog-content .empty').count(),0);
        assert.equal(await page.locator('#dialog-content a').getAttribute('href'),sparse.url);
        await page.keyboard.press('Escape');await page.locator('#catalog-search').fill('');
      }

    }
    const query = cve?.value || snapshot.news[0]?.title.split(' ')[0];
    if (query) {
      await page.locator('#global-search').fill(query);
      await page.locator('#global-search').press('Enter');
      await page.locator('#search-results:not([hidden])').waitFor();
      assert(await page.locator('#search-results .search-hit').count() > 0);
      if(cve)assert.equal(await page.locator('#search-results .search-hit').count(),1);
      await page.getByRole('button', { name: 'Clear search' }).click();
    }

    const campaign=snapshot.records.find(r=>r.source==='circl-osint'&&r.title.includes('MoustachedBouncer'))||snapshot.records.find(r=>r.source==='circl-osint');
    if(campaign){
      await page.locator('#global-search').fill(campaign.title);await page.locator('#global-search').press('Enter');
      const expected=analytics.searchResults(snapshot,campaign.title);
      assert.equal(await page.locator('.search-list > .search-hit').count(),expected.length);
      assert.equal(await page.locator('.search-report').count(),expected.filter(r=>r.type==='report').length);
      const sample=snapshot.records.find(r=>r.source_url===campaign.source_url&&['md5','sha256','url','ip-dst'].includes(r.kind));
      if(sample){
        const query=sample.value.replaceAll('[.]','.').replace('hxxps://','https://').replace('hxxp://','http://');
        await page.locator('#global-search').fill(query);await page.locator('#global-search').press('Enter');
        const hitIndex=analytics.searchResults(snapshot,query).findIndex(hit=>hit.matching.some(r=>r.id===sample.id));
        const hit=page.locator('.search-list > .search-hit').nth(hitIndex);
        await hit.locator('summary').click();
        const exact=hit.locator(`[data-search-record="${sample.id}"]`);
        assert((await exact.innerText()).includes(sample.value));
        await exact.click();await page.locator('dialog[open]').waitFor();
        assert((await page.locator('#dialog-content .indicator').innerText()).includes(sample.value));
        await page.keyboard.press('Escape');
      }
      await page.getByRole('button',{name:'Clear search',exact:true}).click();
    }

    if(expectedStories.length>6){
      await page.locator('[data-more-news]').click();
      assert.equal(await page.locator('.story').count(),expectedStories.length);
      assert.equal(await page.locator('[data-more-news]').innerText(),'Less intelligence ↑');
      assert.equal(await page.locator('[data-more-news]').getAttribute('aria-expanded'),'true');
      await page.locator('[data-more-news]').press('Enter');
      assert.equal(await page.locator('.story').count(),6);
      assert.equal(await page.locator('[data-more-news]').getAttribute('aria-expanded'),'false');
    }
    assert.equal(await page.locator('#context .catalog-note:not(.mitre-credit)').count(),0);
    const counted=[...series].filter(r=>r.count>0).sort((a,b)=>b.count-a.count)[0];
    if(counted){
      const bar=page.locator(`[data-kev-date="${counted.date}"]`);await bar.hover();
      await page.locator('#kev-popover:not([hidden])').waitFor();
      const members=analytics.kevRecords(snapshot.records,30,new Date().toISOString(),counted.date);
      assert.deepEqual(await page.locator('#kev-popover [data-evidence]').allTextContents(),members.slice(0,5).map(r=>r.value));
      const box=await page.locator('#kev-popover').boundingBox();assert(box.x>=0&&box.x+box.width<=1440);
      if(members.length>5){await page.locator('[data-kev-all]').click();await page.locator('#detail-dialog[open]').waitFor();assert.deepEqual(await page.locator('.kev-all [data-evidence]').allTextContents(),members.map(r=>r.value));await page.locator('#detail-dialog .dialog-close').click();}
      await bar.click();await page.keyboard.press('Escape');
      assert(await page.locator('#kev-popover').getAttribute('hidden')!==null);
      await bar.press('Enter');await page.locator('#kev-popover:not([hidden])').waitFor();
      const item=page.locator('#kev-popover [data-evidence]').first();await item.click();
      await page.locator('#detail-dialog[open]').waitFor();
      await page.locator('#dialog-title').click();assert(await page.locator('#detail-dialog').getAttribute('open')!==null);
      assert(await page.locator('html').evaluate(n=>n.classList.contains('modal-open')));
      await page.mouse.click(4,4);assert.equal(await page.locator('#detail-dialog[open]').count(),0);
      await page.waitForFunction(()=>!document.documentElement.classList.contains('modal-open'));
      await page.keyboard.press('Escape');
    }
    await page.locator('#global-search').blur();
    for (const width of [390, 768, 1440]) {
      await page.setViewportSize({ width, height: width === 390 ? 900 : 1050 });
      for (const id of ['context', 'archive', 'vulnerabilities']) {
        await page.locator('#' + id).evaluate(el => { el.open = false; });
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'Horizontal overflow at ' + width);
      if(counted){const bar=page.locator(`[data-kev-date="${counted.date}"]`);await bar.click();const box=await page.locator('#kev-popover').boundingBox();assert(box&&box.x>=0&&box.x+box.width<=width);await page.keyboard.press('Escape');}
      await page.getByRole('button',{name:'Sources & Licenses',exact:true}).click();
      assert.equal(await page.locator('#sources-dialog').evaluate(n=>n.scrollWidth>n.clientWidth),false,'License dialog fits at '+width);
      await page.keyboard.press('Escape');
      if(selected){
        const radar=await page.locator('.radar').boundingBox();
        const evidence=await page.locator('#brief > .supporting-evidence').boundingBox();
        if(radar&&evidence)assert(radar.y>=evidence.y+evidence.height,'Radar follows the main article and evidence');
        const boxes=await page.locator('.radar article').evaluateAll(nodes=>nodes.map(n=>({x:n.getBoundingClientRect().x,y:n.getBoundingClientRect().y})));
        if(boxes.length>1){if(width>650)assert(Math.abs(boxes[0].y-boxes[1].y)<2);else assert(boxes[1].y>boxes[0].y);}
        assert.equal(await page.locator('#brief > .section-head .edition-date').count(),1);
      }

      await page.mouse.move(0,0);await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0);});
      if (output && [390, 1440].includes(width)) {
        fs.mkdirSync(output, { recursive: true });
        await page.screenshot({ path: path.join(output, width === 390 ? 'dashboard-mobile.png' : 'dashboard-desktop.png'), fullPage: true });
      }
    }
    // Isolated presentation fixtures: source validation is exercised by Python.
    // Route overrides never modify the server, source data, or published edition.
    if(selected){
      const fixture=structuredClone(snapshot);fixture.synthetic=true;
      const weekly=structuredClone(selected);weekly.id='weekly-fixture';weekly.publication_kind='weekly';
      const update=structuredClone(weekly);update.id='interim-fixture';update.publication_kind='update';
      update.generated_at=new Date(Date.parse(weekly.generated_at)+3600000).toISOString();
      update.published_at=new Date(Date.parse(analytics.publicationTime(weekly))+3600000).toISOString();
      update.topics[0].headline='Synthetic significant interim development';
      fixture.editions=[update,weekly];
      await page.route('**/snapshot.json',route=>route.fulfill({json:fixture}));
      await page.goto(base);await page.getByRole('heading',{name:'Weekly Brief',exact:true}).waitFor();
      assert.equal(await page.locator('.editorial-lead h1').innerText(),weekly.headline||weekly.topics[0].headline);
      assert.equal(await page.locator('.edition-date').innerText(),analytics.weeklyPeriod(weekly.window_start,weekly.window_end));
      assert.equal(await page.locator('.interim-update').count(),0);
      for(const width of [390,768,1440]){
        await page.setViewportSize({width,height:900});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      }
      await page.unroute('**/snapshot.json');
      fixture.editions=[];fixture.reports=[];fixture.news=[];
      await page.route('**/snapshot.json',route=>route.fulfill({json:fixture}));
      await page.goto(base);await page.getByRole('heading',{name:'Weekly Brief',exact:true}).waitFor();
      assert((await page.locator('#brief').innerText()).includes('No accepted weekly briefing'));
      assert.equal(await page.locator('.editorial-lead,.radar,.interim-update').count(),0);
      await page.unroute('**/snapshot.json');
    }
    if(selected){
      const historical=structuredClone(snapshot);historical.synthetic=true;
      const old=structuredClone(selected);old.id='a'.repeat(24);old.headline='Earlier accepted weekly briefing';old.window_end=selected.window_start;old.window_start=new Date(Date.parse(old.window_end)-7*86400000).toISOString();
      const duplicate={...structuredClone(old),id:'b'.repeat(24),revised_at:'2099-01-01T00:00:00Z'};
      historical.editions=[old,selected,duplicate,...snapshot.editions.filter(e=>e.publication_kind!=='weekly')];
      historical.illustrations=[];
      const art=snapshot.illustrations?.find(a=>a.edition_id===selected.id);
      if(art){historical.illustrations=[{...art,edition_id:duplicate.id}];await page.route('**/assets/briefs/*',route=>route.fulfill({body:art.svg,contentType:'image/svg+xml'}));}
      await page.route('**/snapshot.json',route=>route.fulfill({json:historical}));await page.goto(base);await page.getByRole('heading',{name:'Weekly Brief',exact:true}).waitFor();
      await page.locator('#archive > summary').click();assert.equal(await page.locator('#archive-select option').count(),1);
      assert.equal(await page.locator('#archive-select option').innerText(),analytics.weeklyPeriod(old.window_start,old.window_end));
      assert.equal(await page.locator('.archive-headline').innerText(),old.headline);
      assert.deepEqual(await page.locator('#archived-report .report-overview').allTextContents(),old.plan.overview.map(p=>p.map(c=>c.text).join(' ')));
      if(art)assert((await page.locator('#archived-report img').getAttribute('src')).includes(duplicate.id));
      await page.unroute('**/snapshot.json');if(art)await page.unroute('**/assets/briefs/*');
    }
    if(selected){
      const quiet=structuredClone(snapshot);quiet.synthetic=true;
      const emptyEdition={...structuredClone(selected),id:'q',topics:[],input:{records:[],news:[],updates:[],context:[]},plan:{overview:[[{fact_ids:['quiet'],text:'No source-dated developments in the available feeds.'}]],topics:[]}};
      quiet.editions.unshift(emptyEdition);
      quiet.news=[];
      await page.route('**/snapshot.json',route=>route.fulfill({json:quiet}));
      await page.goto(base);await page.getByRole('heading',{name:'Weekly Brief',exact:true}).waitFor();
      assert.equal(await page.locator('.story').count(),0);
      assert.equal(await page.locator('.editorial-lead h1').innerText(),selected.headline||selected.topics[0].headline);
      assert(!(await page.locator('#brief').innerText()).includes('No source-dated developments'));
      assert.equal(await page.locator('#archive-select option').count(),analytics.visibleHistory(quiet).length);
      const placeholders=structuredClone(snapshot);placeholders.synthetic=true;
      placeholders.news=expectedStories.slice(0,3).map((r,i)=>({...r,excerpt:i===0?'':i===1?'Source excerpt':'A short supported source observation.'}));
      await page.unroute('**/snapshot.json');
      await page.route('**/snapshot.json',route=>route.fulfill({json:placeholders}));
      await page.goto(base);await page.getByRole('heading',{name:'Weekly Brief',exact:true}).waitFor();
      assert(!(await page.locator('#intelligence').innerText()).includes('Source excerpt'));
      assert.equal(await page.locator('.story-excerpt').count(),placeholders.news.length>2?1:0);
      await page.unroute('**/snapshot.json');
    }
    if(counted){
      const touch=await browser.newPage({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
      try{await touch.goto(base);await touch.getByRole('heading',{name:'Weekly Brief',exact:true}).waitFor();
        await touch.locator(`[data-kev-date="${counted.date}"]`).tap();await touch.locator('#kev-popover:not([hidden])').waitFor();
        const box=await touch.locator('#kev-popover').boundingBox();assert(box.x>=0&&box.x+box.width<=390);
        await touch.locator('#kev-popover [data-evidence]').first().tap();await touch.locator('#detail-dialog[open]').waitFor();
        const beforeScroll=await touch.evaluate(()=>scrollY);await touch.mouse.wheel(0,500);assert.equal(await touch.evaluate(()=>scrollY),beforeScroll);
        await touch.touchscreen.tap(2,2);await touch.waitForFunction(()=>!document.querySelector('dialog[open]'));
        if(snapshot.illustrations?.length)assert.equal(await touch.locator('.editorial-lead .weekly-illustration').isVisible(),false);
      }finally{await touch.close();}
    }
    await page.route('**/snapshot.json',route=>route.fulfill({json:{invalid:true}}));
    await page.goto(base);await page.getByRole('heading',{name:'Intelligence unavailable',exact:true}).waitFor();
    assert.equal(await page.locator('#last-updated').count(),0);
    await page.getByRole('button',{name:'Sources & Licenses',exact:true}).click();
    await page.locator('#sources-dialog[open]').waitFor();await page.keyboard.press('Escape');
    await page.unroute('**/snapshot.json');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ status: 'passed', widths: [390, 768, 1440], metrics: actual, stixObjects: snapshot.stix?.objects.length || 0, relationships: snapshot.stix?.relationships.length || 0, errors }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
