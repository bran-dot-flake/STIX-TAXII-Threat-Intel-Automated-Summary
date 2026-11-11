import {metrics, dailyKev, kindCounts, matches} from './analytics.js';

const main = document.querySelector('main');
const dialog = document.querySelector('dialog');
const names = {'cisa-kev':'CISA KEV','circl-osint':'CIRCL OSINT','cisa-advisories':'CISA Advisories'};
const sourceURLs = {'cisa-kev':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog','circl-osint':'https://www.circl.lu/doc/misp/feed-osint/','cisa-advisories':'https://www.cisa.gov/news-events/cybersecurity-advisories'};
const kinds = {'vulnerability':'Known exploited CVEs','ip-dst':'IP addresses',domain:'Domains',url:'URLs',md5:'MD5 hashes',sha1:'SHA-1 hashes',sha256:'SHA-256 hashes'};
const e = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date = value => value ? new Date(value).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric',timeZone:'UTC'}) : 'Not available';
const time = value => value ? `${date(value)} · ${new Date(value).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',timeZone:'UTC'})} UTC` : 'Not available';
const number = value => Number(value).toLocaleString('en-US');
const link = (url, text, cls='') => {
  try {const p = new URL(url); if(p.protocol !== 'https:' || !['www.cisa.gov','www.circl.lu'].includes(p.hostname) || p.username || p.password) return e(text);}
  catch {return e(text);}
  return `<a class="${e(cls)}" href="${e(url)}" target="_blank" rel="noopener noreferrer">${e(text)} ↗</a>`;
};
let data, build = {}, period = 30, newsCategory = 'all', newsLimit = 5, cveQuery = '', cvePage = 0, selectedReport = null;
const empty = (title, body) => `<div class="empty"><h2>${e(title)}</h2><p>${e(body)}</p></div>`;

function edition() {
  const old = !data.collected_at || Date.now() - Date.parse(data.collected_at) > 36*3600000;
  return `<div class="edition"><span><strong>THE DAILY SIGNAL</strong> &nbsp; / &nbsp; PUBLIC-SOURCE INTELLIGENCE</span><span class="freshness"><span class="status-dot"></span>${old ? 'LAST COLLECTION' : 'UPDATED'} ${e(time(data.collected_at))}</span></div>`;
}
function notice() {
  if(data.synthetic) return '<div class="notice">SYNTHETIC DEMONSTRATION · All displayed examples are fictional test intelligence, not operational findings.</div>';
  const failed = data.sources.filter(s=>s.status !== 'ok');
  if(!data.exported_at) return '<div class="notice">DEVELOPMENT PREVIEW · No live intelligence loaded. No example statistics are presented as collected data.</div>';
  const old = Date.now() - Date.parse(data.collected_at) > 36*3600000;
  return (old ? '<div class="notice">Collection is older than 36 hours. This site preserves the last valid publication while the collector is offline.</div>' : '') + (failed.length ? `<div class="notice">${failed.map(s=>e(names[s.id])).join(', ')}: source unavailable. Previously validated data is retained where available. <a href="#sources">View source status ↗</a></div>` : '');
}
function heading(index, title, right='') {return `<div class="section-heading"><h2><span>${index}</span> ${e(title)}</h2>${right}</div>`;}
function overview() {
  const m = metrics(data, new Date().toISOString());
  const latest = data.reports[0];
  const kev = data.records.filter(r=>r.source === 'cisa-kev').slice(0,3);
  main.innerHTML = `${edition()}<div class="masthead"><h1>The threat landscape.<br><em>In perspective.</em></h1><p>A daily lens on emerging cyber risk.<br>Public signals, source-grounded briefings,<br>and the evidence behind them.</p></div>${notice()}
    <section class="metrics" aria-label="Collected intelligence metrics">${[
      ['Tracked KEV entries',m.kev,'Catalog additions · last 90 days','↗'],
      ['Unique public IOCs',m.iocs,`${number(m.newIocs)} first collected in last 24h`,'◎'],
      ['Advisories / 24h',m.news24,'By source publication time','▤'],
      ['Archived briefs',m.briefs,'Validated, source-linked editions','↗'],
      ['Recent advisories',m.advisories,'Up to 18 · last 30 days','⌁'],
    ].map(([label,value,note,icon])=>`<div class="metric"><div class="metric-label">${e(label)}<span aria-hidden="true">${icon}</span></div><div class="metric-value">${number(value)}</div><small>${e(note)}</small></div>`).join('')}</section>
    <section aria-label="Daily intelligence brief">${heading('01','THE INTELLIGENCE BRIEF','<a href="#briefings">All editions ↗</a>')}
    <div class="brief-grid"><div class="brief-main"><div class="eyebrow">DAILY INTELLIGENCE <span class="chip">${latest?.mode === 'ollama-extractive' ? 'LLM-ASSISTED' : 'EVIDENCE-LED'}</span></div>
      ${latest ? `<h2>${e(latest.items[0]?.title || 'The daily intelligence brief')}</h2><p>${e(latest.items[0]?.excerpt || 'No new or changed observations in the bounded local report batch. This does not imply an absence of threats; continue reviewing the current public feeds below.')}</p><div class="brief-meta"><span>${e(date(latest.generated_at))}</span><span>•</span><span>${latest.evidence_count} source observations</span><a class="text-link" href="#briefings">Read the full briefing ↗</a></div>` : '<h2>Evidence before analysis.</h2><p>No validated public brief is available yet. Original public-source intelligence remains available below; the next accepted local report will appear here automatically.</p><div class="brief-meta"><a class="text-link" href="#sources">How the briefing works ↗</a></div>'}
      </div><aside class="brief-aside"><div class="kicker">ON THE RADAR / RECENT KEV ADDITIONS</div>${kev.length ? kev.map(r=>`<button class="watch-item" data-detail="${e(r.id)}"><span>${e(r.value)} <i aria-hidden="true">↗</i></span><p>${e(r.title)}</p></button>`).join('') : '<p class="muted">No recent KEV records available.</p>'}</aside></div></section>
    <section aria-label="Intelligence analytics"><div class="analytics-grid"><div class="panel"><div class="panel-head"><div><h2 class="panel-title">The exploitation watch</h2><p class="panel-subtitle">CISA KEV catalog additions / UTC</p></div><div class="segmented" aria-label="Chart period"><button data-period="7" aria-pressed="${period===7}">7D</button><button data-period="30" aria-pressed="${period===30}">30D</button></div></div><div id="trend"></div></div>
      <div class="panel"><div class="panel-head"><div><h2 class="panel-title">Inside the collection</h2><p class="panel-subtitle">Unique values by evidence type</p></div><span class="muted" aria-hidden="true">◫</span></div><div class="type-list">${types()}</div><p class="chart-note">Source observations, deduplicated by type and value. KEV inclusion means known exploitation; it is not a CVSS severity score.</p></div></div></section>
    <section class="news-section" aria-label="Latest intelligence reports">${heading('02','FROM THE INTELLIGENCE DESK',`<div class="news-tools" aria-label="News category">${[['all','All stories'],['Exploitation watch','Exploitation'],['Security advisory','Advisories']].map(([v,l])=>`<button data-news-category="${v}" aria-pressed="${newsCategory===v}">${l}</button>`).join('')}</div>`)}<div id="news-content"></div></section>`;
  document.querySelectorAll("[data-width]").forEach(el=>el.style.width=`${el.dataset.width}%`);
  trend(); news();
}
function types() {
  const counts = kindCounts(data.records); const max = Math.max(...counts.map(r=>r[1]),1);
  return counts.length ? counts.map(([kind,count])=>`<div class="type-row"><header><span>${e(kinds[kind]||kind)}</span><b>${number(count)}</b></header><div class="type-track" role="img" aria-label="${e(kinds[kind]||kind)}: ${count}"><span class="type-bar" data-width="${count/max*100}"></span></div></div>`).join('') : '<p class="muted">No observations available.</p>';
}
function trend() {
  const rows = dailyKev(data.records, period, new Date().toISOString()); const total = rows.reduce((s,r)=>s+r.count,0); const max = Math.max(...rows.map(r=>r.count),1);
  document.querySelector('#trend').innerHTML = `<div class="chart-total">${number(total)}<small>entries added in ${period} days</small></div><div class="bar-chart" role="group" aria-label="Daily KEV additions"><span class="axis-max">${max}</span>${rows.map(r=>`<div class="bar-slot"><button class="bar" data-height="${r.count/max*100}" aria-label="${r.date}: ${r.count} catalog additions"><span class="bar-tip">${e(date(r.date))}: ${r.count}</span></button></div>`).join('')}</div><div class="chart-axis"><span>${e(date(rows[0].date))}</span><span>${e(date(rows.at(-1).date))}</span></div><details><summary>View chart data & methodology</summary><p>Daily unique CVEs by catalog dateAdded, not vulnerability disclosure or exploitation date. Source failures may leave cached coverage incomplete.</p><table class="data-table"><thead><tr><th scope="col">UTC date</th><th scope="col">Catalog additions</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${r.date}</td><td>${r.count}</td></tr>`).join('')}</tbody></table></details>`;
  document.querySelectorAll("[data-height]").forEach(el=>el.style.height=`${el.dataset.height}%`);
}
function news() {
  const rows = data.news.filter(r=>newsCategory==='all'||r.category===newsCategory);
  document.querySelector('#news-content').innerHTML = rows.length ? `<div class="news-grid">${rows.slice(0,newsLimit).map(r=>`<article class="story"><img src="./assets/${r.artwork==='exploitation.svg'?'exploitation.svg':'advisory.svg'}" alt="" loading="lazy" width="900" height="560"><div class="eyebrow">${e(r.category)}</div><h3>${link(r.source_url,r.title)}</h3><p>${e(r.excerpt)}</p><div class="story-meta"><span>CISA · ${e(date(r.published_at))}</span>${link(r.source_url,'Read source')}</div></article>`).join('')}</div>${rows.length>newsLimit?'<button class="load-more" data-more>MORE FROM THE DESK ↓</button>':''}<p class="chart-note">Short excerpts from original CISA advisories. Illustrations: original EMBER editorial artwork; not source photographs. Headlines are source-reported.</p>` : empty('The desk is quiet.', 'No recent advisories match this filter. Try another category or check source status.');
}
function reportMarkup(report) {
  return `<div class="eyebrow">DAILY INTELLIGENCE / ${e(date(report.generated_at))}</div><h2>The daily intelligence brief</h2><p class="context">${report.evidence_count} source observations · ${report.mode==='ollama-extractive'?'Ollama selected, validated source excerpts':'Deterministic evidence selection'}. This bounded briefing highlights source assertions. Local exposure and independent attribution have not been assessed.</p>${report.mode==='quiet-day'?'<div class="evidence"><h3>No new findings in this report batch.</h3><p>The collector reported no new or changed observations in its configured window. This does not imply an absence of threats. Continue routine monitoring and review source health.</p></div>':''}${report.items.map((r,i)=>`<article class="evidence"><div class="eyebrow">FINDING ${String(i+1).padStart(2,'0')} / ${e(names[r.source])}</div><h3>${e(r.title)}</h3><p>${e(r.excerpt)}</p><div class="detail-value">${e(r.value)}</div><div class="action"><b>Defensive consideration</b><br>${e(r.action)}</div><p class="evidence-source">${link(r.source_url,'Original evidence')} · ${e(date(r.published_at))}${r.source==='cisa-kev'?' (catalog added)':''}</p></article>`).join('')}<p class="chart-note">The model selects complete source excerpts; it does not generate statistics, invent relationships, or assess your environment. Public briefs exclude private platform context. Only reports whose complete evidence batch passes the publication gate appear here.</p>`;
}
function briefings() {
  if(!selectedReport || !data.reports.some(r=>r.id===selectedReport)) selectedReport = data.reports[0]?.id;
  const selected = data.reports.find(r=>r.id===selectedReport);
  main.innerHTML = `${edition()}<h1 class="page-title">The briefing room.</h1><p class="page-description">Daily intelligence, with the evidence attached. Explore up to 90 validated public editions from the local reporting pipeline.</p>${notice()}${selected ? `<div class="archive"><div class="archive-list" aria-label="Briefing editions">${data.reports.map(r=>`<button class="archive-button" data-report="${e(r.id)}" aria-pressed="${r.id===selectedReport}"><time>${e(time(r.generated_at))}</time><strong>${e(r.items[0]?.title || 'Daily intelligence brief')}</strong><small>${r.evidence_count} observations · ${r.mode==='ollama-extractive'?'LLM-assisted':'Deterministic'}</small></button>`).join('')}</div><article class="report-body" id="selected-brief">${reportMarkup(selected)}</article></div>` : empty('Awaiting a public edition.', 'The original-source collection can operate independently of MISP, OpenCTI, and Ollama. A validated local brief will be added after its source evidence passes the public export gate.')}`;
}
function vulnerabilities() {
  main.innerHTML = `${edition()}<h1 class="page-title">The exploitation register.</h1><p class="page-description">Known exploited vulnerabilities added to CISA's catalog within the last 90 days. Catalog inclusion signals exploitation in the wild; it does not establish local exposure or a CVSS score.</p>${notice()}<div class="filter-row"><label class="sr-only" for="cve-search">Filter vulnerabilities</label><input type="search" id="cve-search" placeholder="Filter by CVE, vendor, or vulnerability…" value="${e(cveQuery)}"><span id="cve-count"></span></div><div id="cve-results"></div>`;
  cveRows();
}
function cveRows() {
  const rows = data.records.filter(r=>r.source==='cisa-kev' && matches(r,cveQuery));
  cvePage = Math.min(cvePage,Math.max(0,Math.ceil(rows.length/20)-1));
  document.querySelector('#cve-count').textContent = `${number(rows.length)} entries`;
  document.querySelector('#cve-results').innerHTML = rows.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th scope="col">CVE / DETAIL</th><th scope="col">VULNERABILITY</th><th scope="col">CATALOG ADDED</th><th scope="col">STATUS</th></tr></thead><tbody>${rows.slice(cvePage*20,cvePage*20+20).map(r=>`<tr><td><button class="cve-button" data-detail="${e(r.id)}">${e(r.value)} ↗</button></td><td class="table-title">${e(r.title)}</td><td>${e(date(r.published_at))}</td><td><span class="badge">KNOWN EXPLOITED</span></td></tr>`).join('')}</tbody></table></div><div class="pagination"><button data-page="-1" ${cvePage===0?'disabled':''}>← Previous</button><span>Page ${cvePage+1} of ${Math.ceil(rows.length/20)}</span><button data-page="1" ${(cvePage+1)*20>=rows.length?'disabled':''}>Next →</button></div>` : empty('No matching vulnerabilities.', 'Try a different CVE, vendor, or keyword.');
}
function sources() {
  main.innerHTML = `${edition()}<h1 class="page-title">Follow the evidence.</h1><p class="page-description">A transparent view of the collection, publication boundary, and timestamps behind this observatory.</p>${notice()}<div class="health-grid">${Object.entries(names).map(([id,name])=>{
    const source = data.sources.find(s=>s.id===id); return `<section class="health-card"><h2>${name}</h2><div class="health ${e(source?.status||'unavailable')}"><span class="status-dot"></span>${e(source?.status==='ok'?'Last fetch successful':source?.status||'Not collected')}</div><p>LAST ATTEMPT<br>${e(time(source?.attempted_at))}</p><p>LAST SUCCESS<br>${e(time(source?.last_success_at))}</p>${link(sourceURLs[id],'Visit original source')}</section>`;
  }).join('')}</div><div class="method-grid"><section class="panel"><h2>Three clocks. One publication.</h2><dl class="timestamps"><div><dt>Latest successful source collection</dt><dd>${e(time(data.collected_at))}</dd></div><div><dt>Latest public brief generated</dt><dd>${e(time(data.reports[0]?.generated_at))}</dd></div><div><dt>Sanitized export created</dt><dd>${e(time(data.exported_at))}</dd></div><div><dt>This website build</dt><dd>${e(time(build.built_at))}</dd></div></dl><p>Build time precedes publication. The exact deployment result and completion time are recorded in the <a class="text-link" href="https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/workflows/pages.yml" target="_blank" rel="noopener noreferrer">public deployment log ↗</a>. The website stays online while the local collector is offline.</p></section><section class="panel"><h2>Public by construction.</h2><p>Original allowlisted public sources → normalized evidence → optional local MISP / OpenCTI context → Ollama excerpt selection → validated public JSON → GitHub Actions → this static website.</p><p>The publisher recollects original public evidence. It never copies the local database, raw reports, private events, credentials, or platform context. CIRCL events require explicit CLEAR / WHITE markings; conflicting restrictions and nonpublic indicators are withheld.</p><p>Counts use deterministic code. No severity, malware, actor, or ATT&CK relationships are inferred. IOC values are defanged and never linked. First-collected metrics begin with this publication's initial collection, not historic source discovery.</p></section></div>`;
}
function search() {
  const query = new URLSearchParams(location.hash.split('?')[1]||'').get('q')||'';
  const hits = [...data.news,...data.records].filter(r=>matches(r,query)).slice(0,80);
  main.innerHTML = `${edition()}<h1 class="page-title query-text">Search: ${e(query)}</h1><p class="page-description">${hits.length===80?'First 80':hits.length} results across collected records and source advisories.</p><div class="search-results">${hits.length ? hits.map(r=>`<article class="search-hit"><div class="eyebrow">${e(names[r.source])} / ${e(date(r.published_at))}</div><h2>${r.kind ? `<button class="cve-button" data-detail="${e(r.id)}">${e(r.title)} ↗</button>` : link(r.source_url,r.title)}</h2><p>${e(r.value||r.excerpt||'')}</p></article>`).join('') : empty('No matching intelligence.', 'Try a CVE, indicator, vendor, or a keyword from a source headline.')}</div>`;
}
function detail(id) {
  const row = data.records.find(r=>r.id===id); if(!row) return;
  document.querySelector('#dialog-content').innerHTML = `<div class="eyebrow">${e(names[row.source])} / EVIDENCE DETAIL</div><h2 class="dialog-title" id="dialog-title">${e(row.title)}</h2><div class="detail-value">${e(row.value)}</div><div class="detail-content"><p>${e(row.description)}</p><h3>Defensive consideration</h3><p>${e(row.action)}</p><h3>Source & chronology</h3><dl><dt>${row.source==='cisa-kev'?'Catalog added':'Source published'}</dt><dd>${e(time(row.published_at))}</dd><dt>First collected by this publication</dt><dd>${e(time(row.first_seen))}</dd><dt>Last collected</dt><dd>${e(time(row.last_seen))}</dd></dl><p>${link(row.source_url,'Open original evidence')}</p><p class="chart-note">Source assertions are not independent verification. No local exposure, actor attribution, or relationships are inferred. Indicators are defanged for safe reading.</p></div>`;
  dialog.showModal();
}
function render() {
  const view = location.hash.slice(1).split('?')[0] || 'overview';
  document.querySelectorAll('[data-view]').forEach(a=>a.setAttribute('aria-current',a.dataset.view===view?'page':'false'));
  document.querySelector('#view-label').textContent = ({overview:'OVERVIEW',briefings:'DAILY BRIEFS',vulnerabilities:'VULNERABILITIES',sources:'SOURCES & STATUS',search:'SEARCH'})[view]||'OVERVIEW';
  ({overview,briefings,vulnerabilities,sources,search}[view]||overview)();
  document.title = `EMBER — ${document.querySelector('#view-label').textContent}`;
}
main.addEventListener('click',event=>{
  const button = event.target.closest('button'); if(!button) return;
  if(button.dataset.detail) detail(button.dataset.detail);
  if(button.dataset.period) {period=Number(button.dataset.period); document.querySelectorAll('[data-period]').forEach(b=>b.setAttribute('aria-pressed',Number(b.dataset.period)===period)); trend();}
  if(button.dataset.newsCategory) {newsCategory=button.dataset.newsCategory; newsLimit=5; document.querySelectorAll('[data-news-category]').forEach(b=>b.setAttribute('aria-pressed',b.dataset.newsCategory===newsCategory)); news();}
  if(button.hasAttribute('data-more')) {const previous=newsLimit; newsLimit+=6; news(); document.querySelectorAll('.story')[previous]?.querySelector('a')?.focus();}
  if(button.dataset.report) {selectedReport=button.dataset.report; briefings(); const article=document.querySelector('#selected-brief'); article.tabIndex=-1; article.focus(); article.scrollIntoView({block:'start'});}
  if(button.dataset.page) {const direction=button.dataset.page; cvePage+=Number(direction); cveRows(); const buttons=[...document.querySelectorAll('[data-page]:not(:disabled)')]; (buttons.find(b=>b.dataset.page===direction)||buttons[0])?.focus();}
});
main.addEventListener('input',event=>{if(event.target.id==='cve-search'){cveQuery=event.target.value; cvePage=0; cveRows();}});
document.querySelector('#search-form').addEventListener('submit',event=>{event.preventDefault(); const q=document.querySelector('#global-search').value.trim(); if(q) location.hash=`search?q=${encodeURIComponent(q)}`;});
document.querySelector('.dialog-close').addEventListener('click',()=>dialog.close());
dialog.addEventListener('click',event=>{if(event.target===dialog){const r=dialog.getBoundingClientRect(); if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom) dialog.close();}});
window.addEventListener('hashchange',()=>{if(!data)return;render();window.scrollTo(0,0);main.focus({preventScroll:true});});
try {
  const response = await fetch('./snapshot.json',{cache:'no-cache'}); if(!response.ok) throw new Error('Data unavailable');
  data = await response.json();
  if(data.schema_version!==1 || typeof data.synthetic!=='boolean' || !['records','reports','news','sources'].every(k=>Array.isArray(data[k]))) throw new Error('Invalid publication');
  try {const r=await fetch('./build.json',{cache:'no-cache'});if(r.ok) build=await r.json();} catch {}
  render();
} catch {
  main.innerHTML = empty('The observatory is temporarily unavailable.', 'The public data file could not be loaded. Refresh to retry, or visit the project repository for deployment status. No live connection to the local lab is required.');
}
