import {metrics, dailyKev, kindCounts, matches, groupStories, briefDigest, editorialStories} from './analytics.js';

const main = document.querySelector('main');
const dialog = document.querySelector('dialog');
const names = {'cisa-kev':'CISA KEV','circl-osint':'CIRCL OSINT','cisa-advisories':'CISA','mitre-enterprise':'MITRE ATT&CK®'};
const kinds = {'vulnerability':'CVEs','ip-dst':'IP addresses',domain:'Domains',url:'URLs',md5:'MD5',sha1:'SHA-1',sha256:'SHA-256'};
const types = {'attack-pattern':'Technique','intrusion-set':'Group',malware:'Malware',tool:'Tool'};
const e = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date = value => value ? new Date(value).toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric',timeZone:'UTC'}) : 'Not available';
const time = value => value ? `${date(value)} · ${new Date(value).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',timeZone:'UTC'})} UTC` : 'Not available';
const num = value => Number(value).toLocaleString('en-US');
const shortHeadline = title => title.length>105?title.slice(0,102).replace(/\s+\S*$/,'')+'…':title;
const link = (url,text,cls='') => {
  try {const p=new URL(url);if(p.protocol!=='https:'||!['www.cisa.gov','www.circl.lu','attack.mitre.org'].includes(p.hostname)||p.username||p.password)return e(text);}
  catch {return e(text);}
  return `<a class="${e(cls)}" href="${e(url)}" target="_blank" rel="noopener noreferrer">${e(text)} ↗</a>`;
};
let data, period=30, newsFilter='all', newsLimit=6, cveQuery='', cvePage=0, catalogQuery='', catalogType='all', catalogLimit=12;
const empty = text => `<p class="empty">${e(text)}</p>`;

function warnings() {
  if(data.synthetic)return '<div class="notice">Synthetic demonstration — fictional examples, not operational intelligence.</div>';
  if(!data.exported_at)return '<div class="notice">Development preview — no collected data loaded.</div>';
  const stale = !data.collected_at || Date.now()-Date.parse(data.collected_at)>36*3600000;
  const failed = data.sources.filter(s=>s.status!=='ok');
  return (stale?'<div class="notice">Collection is over 36 hours old. Showing the last valid dataset.</div>':'')+(failed.length?`<div class="notice">${failed.map(s=>e(names[s.id])).join(', ')} unavailable; showing retained data where available.</div>`:'');
}

const freshness = {'catalog-added':'Catalog addition','newly-published':'New publication','source-updated':'Source updated','newly-collected-history':'Newly collected · historical','historical-context':'Historical context',undated:'Publication date unavailable'};
const prose = clauses => (clauses||[]).map(c=>c.text).join(' ');
function topicMarkup(topic,technical=false) {
  const rows=topic.records;
  const sources=[...new Map(rows.map(r=>[r.source_url,r])).values()];
  return `<article class="${technical?'report-topic':'finding'}"><div class="source-line">${e(freshness[topic.freshness])}</div><h3>${e(topic.headline)}</h3><p>${e(prose(topic.summary)||rows[0]?.excerpt)}</p>${topic.why_it_matters?`<p class="significance">${e(topic.why_it_matters.text)}</p>`:''}<div class="topic-sources">${sources.map(r=>link(r.source_url,names[r.source])).join(' · ')}</div>${technical?`<details class="topic-evidence"><summary>Technical evidence · ${rows.length}</summary>${rows.map(row=>`<article class="evidence"><div class="indicator">${e(row.kind)} · ${e(row.value)}</div><p>${e(row.excerpt)}</p><dl><dt>${row.source==='cisa-kev'?'Catalog added':'Source published'}</dt><dd>${e(time(row.published_at))}</dd>${row.modified_at?`<dt>Source modified</dt><dd>${e(time(row.modified_at))}</dd>`:''}${row.first_seen?`<dt>First collected / last seen</dt><dd>${e(time(row.first_seen))} / ${e(time(row.last_seen))}</dd>`:''}</dl>${link(row.source_url,'Original source','link')}</article>`).join('')}</details>`:''}</article>`;
}
function reportMarkup(report) {
  const topics=briefDigest(report);
  const covered=new Set(topics.flatMap(t=>t.records.map(r=>r.id)));
  const withheld=(report.observations||report.items).filter(r=>!covered.has(r.id));
  const defaultAction='Review indicator against local telemetry before taking action.';
  const actions=new Map();
  for(const topic of topics)for(const row of topic.records){if(row.action&&row.action!==defaultAction){if(!actions.has(row.action))actions.set(row.action,new Map());actions.get(row.action).set(row.source_url,row);}}
  return `<div class="metadata">${e(time(report.generated_at))} · ${report.evidence_count} source observations · ${report.narrative?.mode==='ollama-grounded'?'Ollama fact-cited composition':'Source-grounded fallback'}</div>${report.narrative?`<p class="report-overview">${e(prose(report.narrative.plan.overview))}</p>`:''}${topics.map(t=>topicMarkup(t,true)).join('')}${withheld.length?`<details class="topic-evidence"><summary>Source metadata requires review · ${withheld.length}</summary>${withheld.map(row=>`<article class="evidence"><div class="indicator">${e(row.kind)} · ${e(row.value)}</div>${link(row.source_url,'Original source','link')}</article>`).join('')}</details>`:''}${actions.size?`<div class="source-actions"><h3>Source defensive considerations</h3>${[...actions].map(([action,sources])=>`<p>${e(action)} <span class="topic-sources">${[...sources.values()].map(r=>link(r.source_url,names[r.source])).join(' · ')}</span></p>`).join('')}</div>`:''}`;
}

function editionRows(edition) {
  return [...edition.input.records,...edition.input.news,...edition.input.updates].filter((row,index,rows)=>rows.findIndex(r=>r.id===row.id)===index);
}
function editorialTopics(edition) {
  const rows=editionRows(edition);
  return edition.topics.map(topic=>({...topic,records:rows.filter(r=>topic.evidence_ids.includes(r.id)),summary:edition.plan.topics.find(t=>t.topic_id===topic.id)?.summary.text||''}));
}
function editionMarkup(edition) {
  const topics=editorialTopics(edition);
  const actions=[...new Set(topics.flatMap(t=>t.records.map(r=>r.action)).filter(Boolean))];
  return `<div class="metadata">${e(time(edition.generated_at))} · ${edition.mode==='ollama-source-grounded'?'Ollama source-grounded composition':'Source-grounded fallback'}</div>${edition.plan.overview.map(p=>`<p class="report-overview">${e(prose(p))}</p>`).join('')}${topics.map(topic=>`<article class="report-topic"><div class="source-line">${e(freshness[topic.freshness])} · ${e(date(topic.published_at))}</div><h3>${e(topic.headline)}</h3><p>${e(topic.summary)}</p><details class="topic-evidence"><summary>Supporting evidence · ${topic.records.length}</summary>${topic.records.map(row=>`<article class="evidence"><div class="source-line">${e(names[row.source])}</div><h4>${e(row.value||row.title)}</h4><p>${e(row.description||row.excerpt)}</p><dl><dt>${row.source==='cisa-kev'?'Catalog added':'Source published'}</dt><dd>${e(date(row.published_at))}</dd>${row.modified_at?`<dt>Source modified</dt><dd>${e(time(row.modified_at))}</dd>`:''}${row.first_seen?`<dt>First collected / last seen</dt><dd>${e(time(row.first_seen))} / ${e(time(row.last_seen))}</dd>`:''}</dl>${link(row.source_url,'Original source','link')}</article>`).join('')}${(topic.context_ids||[]).map(id=>{const obj=edition.input.context.find(o=>o.id===id);return obj?`<p>${link(obj.url,`${obj.external_id} · ${obj.name}`)}</p>`:''}).join('')}</details></article>`).join('')}${actions.length?`<details class="source-actions"><summary>Source defensive guidance</summary>${actions.map(action=>`<p>${e(action)}</p>`).join('')}</details>`:''}`;
}
const archives = () => [...(data.editions||[]),...data.reports].sort((a,b)=>b.generated_at.localeCompare(a.generated_at));
function opening(edition,report) {
  if(!edition){const digest=briefDigest(report);return `<div class="section-head"><h1>Daily Brief</h1><time>${e(date(report?.generated_at))}</time></div>${report?.narrative?`<p class="brief-overview">${e(prose(report.narrative.plan.overview))}</p>`:''}${digest.length?`<div class="brief-findings">${digest.map(row=>topicMarkup(row)).join('')}</div>`:empty('No accepted public edition is available yet.')}${report?`<details class="full-brief"><summary>Full brief and evidence</summary><div class="report-body">${reportMarkup(report)}</div></details>`:''}`;}
  const topics=editorialTopics(edition);
  const radar=topics.length>1?topics.slice(1,4):topics;
  const sources=[...new Map(topics.flatMap(t=>t.records).map(r=>[r.source_url,r])).values()];
  return `<div class="section-head"><h2>Daily Brief</h2><time>${e(date(edition.generated_at))}</time></div><div class="edition-grid"><div class="editorial-lead"><h1>${e(topics[0]?.headline||'No new source-dated developments')}</h1>${edition.plan.overview.map(p=>`<p class="brief-overview">${e(prose(p))}</p>`).join('')}<div class="topic-sources">${sources.slice(0,3).map(r=>link(r.source_url,names[r.source])).join(' · ')}</div></div>${radar.length?`<aside class="radar" aria-labelledby="radar-title"><h2 id="radar-title">On the radar</h2>${radar.map(topic=>`<article><div class="source-line">${e(date(topic.published_at))} · ${e(freshness[topic.freshness])}</div><h3>${e(topic.headline)}</h3><p>${e(topic.summary)}</p><div class="topic-sources">${[...new Map(topic.records.map(r=>[r.source_url,r])).values()].map(r=>link(r.source_url,names[r.source])).join(' · ')}</div></article>`).join('')}</aside>`:''}</div><details class="full-brief"><summary>Full brief and evidence</summary><div class="report-body">${editionMarkup(edition)}</div></details>`;
}

function render() {
  const report=data.reports[0];
  const edition=data.editions?.[0];
  const history=archives();
  const m=metrics(data,new Date().toISOString());
  const week=dailyKev(data.records,7,new Date().toISOString()).reduce((sum,row)=>sum+row.count,0);
  main.innerHTML=`${warnings()}<section id="search-results" class="search-results" hidden></section>
    <section class="brief" id="brief">${opening(edition,report)}</section>
    <section id="intelligence"><div class="section-head"><h2>Latest Intelligence</h2><div class="news-filters" aria-label="News category">${[['all','All'],['Security advisory','Advisories'],['Exploitation watch','KEV']].map(([v,l])=>`<button data-news-filter="${v}" aria-pressed="${v===newsFilter}">${l}</button>`).join('')}</div></div><div id="news-content"></div></section>
    <section class="metrics" aria-label="Collection statistics">${[[week,'KEV additions · 7d'],[m.iocs,'Unique public IOCs'],[m.advisories,'Selected advisories'],[history.length,'Archived briefs']].map(([count,label])=>`<div class="metric"><strong>${num(count)}</strong><span>${label}</span></div>`).join('')}</section>
    <section id="trends"><div class="section-head"><h2>Trends</h2><div class="segmented" aria-label="Chart period"><button data-period="7" aria-pressed="${period===7}">7D</button><button data-period="30" aria-pressed="${period===30}">30D</button></div></div>
      <div class="trend-grid"><div><div class="chart-head"><h3>KEV catalog additions</h3><span id="chart-total"></span></div><div id="trend"></div></div>
      <details class="collection-composition"><summary>Dataset composition · unique values by type</summary><div id="types" class="type-list"></div></details></div></section>
      <details id="context" class="context"><summary>MITRE ATT&CK® context <small>${data.stix.objects.length} catalog objects · ${data.stix.relationships.length} source relationships</small></summary>
        <p class="catalog-note">Catalog context, not incident activity. ${data.stix.collected_at?'Collected '+e(date(data.stix.collected_at))+'.':''}${data.stix.status==='cached'?' Source unavailable; retained data.':''}</p>
        <div class="filter-row"><label class="sr-only" for="catalog-search">Search catalog context</label><input id="catalog-search" type="search" placeholder="Technique, software, or group…"><label class="sr-only" for="catalog-type">Catalog type</label><select id="catalog-type"><option value="all">All types</option><option value="attack-pattern">Techniques</option><option value="intrusion-set">Groups</option><option value="malware">Malware</option><option value="tool">Tools</option></select></div><div id="catalog-results"></div></details>

    <details class="register" id="vulnerabilities"><summary>Vulnerabilities <small>${m.kev} KEV entries</small></summary><div class="filter-row"><label class="sr-only" for="cve-search">Filter vulnerabilities</label><input id="cve-search" type="search" placeholder="CVE, vendor, or keyword…"><small id="cve-count"></small></div><div id="cve-results"></div></details>
    <details class="archive" id="archive"><summary>Archive <small>${history.length} briefs</small></summary><div class="filter-row"><label for="archive-select">Edition</label><select id="archive-select">${history.map(row=>`<option value="${e(row.id)}">${e(time(row.generated_at))} · ${row.input?'Daily edition':'Evidence brief'}</option>`).join('')}</select></div><div id="archived-report" class="report-body">${history[0]?(history[0].input?editionMarkup(history[0]):reportMarkup(history[0])):empty('No accepted public editions yet.')}</div></details>`;
  document.querySelector('#last-updated').textContent=data.collected_at?`Updated ${time(data.collected_at)}`:'No collection yet';
  document.querySelector('#attribution').innerHTML=data.stix.objects.length?`MITRE ATT&CK® data © 2015–2026 The MITRE Corporation. ${link(data.stix.license,'Terms of use')}`:'';
  trend();typeChart();news();cveRows();catalog();
}

function trend() {
  const rows=dailyKev(data.records,period,new Date().toISOString());
  const max=Math.max(...rows.map(r=>r.count),1);
  document.querySelector('#chart-total').textContent=`${rows.reduce((sum,r)=>sum+r.count,0)} / ${period} days`;
  document.querySelector('#trend').innerHTML=`<div class="bar-chart" role="group" aria-label="Daily KEV catalog additions">${rows.map(r=>`<div class="bar-slot"><button class="bar" data-height="${r.count/max*100}" aria-label="${r.date}: ${r.count} catalog additions"><span class="bar-tip">${e(date(r.date))}: ${r.count}</span></button></div>`).join('')}</div><div class="chart-axis"><span>${e(date(rows[0].date))}</span><span>${e(date(rows.at(-1).date))}</span></div><details class="chart-data"><summary>Chart data</summary><table class="data-table"><caption class="sr-only">KEV additions by catalog date, UTC</caption><thead><tr><th scope="col">Date (UTC)</th><th scope="col">Additions</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${r.date}</td><td>${r.count}</td></tr>`).join('')}</tbody></table></details>`;
  document.querySelectorAll('[data-height]').forEach(el=>el.style.height=`${el.dataset.height}%`);
}

function typeChart() {
  const rows=kindCounts(data.records);const max=Math.max(...rows.map(r=>r[1]),1);
  document.querySelector('#types').innerHTML=rows.length?rows.map(([kind,count])=>`<div class="type-row"><span>${e(kinds[kind]||kind)}</span><div class="type-track" role="img" aria-label="${e(kinds[kind]||kind)}: ${count}"><span class="type-bar" data-width="${count/max*100}"></span></div><b>${count}</b></div>`).join(''):empty('No observations available.');
  document.querySelectorAll('[data-width]').forEach(el=>el.style.width=`${el.dataset.width}%`);
}

function news() {
  const stories=editorialStories(data.news,data.exported_at||new Date().toISOString(),data.editions?.[0]?.topics.flatMap(t=>t.evidence_ids)||[]).filter(r=>newsFilter==='all'||r.category===newsFilter);
  document.querySelector('#news-content').innerHTML=stories.length?`<div class="news-grid">${stories.slice(0,newsLimit).map((row,index)=>{
    return `<article class="story ${index===0?'story-featured':index>=3?'story-brief':'story-secondary'}"><div class="source-line">CISA · ${e(date(row.published_at))}</div><h3 title="${e(row.title)}">${link(row.source_url,shortHeadline(row.title))}</h3><details class="story-excerpt"><summary title="Expand or collapse full source excerpt"><span class="story-preview">${e(row.excerpt)}</span><span class="excerpt-close">Collapse excerpt</span></summary><p>${e(row.excerpt)}</p></details>${row.related.length?`<details class="related-updates"><summary>${row.related.length} related source updates</summary><ul>${row.related.map(r=>`<li>${link(r.source_url,date(r.published_at))} — ${e(r.title)}</li>`).join('')}</ul></details>`:''}<div class="story-meta"><span>${e(row.category)}</span>${link(row.source_url,'Read source')}</div></article>`;
  }).join('')}</div>${stories.length>newsLimit?'<button class="more" data-more-news>More intelligence ↓</button>':''}`:empty('No recent source reports match this filter.');
}

function cveRows() {
  const rows=data.records.filter(r=>r.source==='cisa-kev'&&matches(r,cveQuery));
  cvePage=Math.min(cvePage,Math.max(0,Math.ceil(rows.length/10)-1));
  document.querySelector('#cve-count').textContent=`${rows.length} matching entries`;
  document.querySelector('#cve-results').innerHTML=rows.length?`<div class="table-wrap"><table class="data-table"><thead><tr><th scope="col">CVE</th><th scope="col">Vulnerability</th><th scope="col">Catalog added</th></tr></thead><tbody>${rows.slice(cvePage*10,cvePage*10+10).map(row=>`<tr><td><button class="link" data-evidence="${e(row.id)}">${e(row.value)} ↗</button></td><td class="table-title">${e(row.title)}</td><td>${e(date(row.published_at))}</td></tr>`).join('')}</tbody></table></div><div class="pagination"><button data-page="-1" ${cvePage===0?'disabled':''}>← Previous</button><span>${cvePage+1} / ${Math.ceil(rows.length/10)}</span><button data-page="1" ${(cvePage+1)*10>=rows.length?'disabled':''}>Next →</button></div>`:empty('No matching vulnerabilities.');
}

function catalog() {
  const rows=data.stix.objects.filter(row=>(catalogType==='all'||row.type===catalogType)&&matches(row,catalogQuery));
  document.querySelector('#catalog-results').innerHTML=rows.length?`<div class="catalog-grid">${rows.slice(0,catalogLimit).map(row=>`<button class="catalog-item" data-stix="${e(row.id)}"><span>${e(row.external_id)} · ${e(types[row.type]||row.type)}</span><strong>${e(row.name)}</strong></button>`).join('')}</div>${rows.length>catalogLimit?'<button class="more" data-more-catalog>More catalog context ↓</button>':''}`:empty('No matching catalog objects.');
}

function evidence(id) {
  const row=data.records.find(r=>r.id===id)||[...data.reports.flatMap(r=>r.observations||r.items),...(data.editions||[]).flatMap(editionRows)].find(r=>r.id===id);if(!row)return;
  document.querySelector('#dialog-content').innerHTML=`<div class="source-line">${e(names[row.source])}</div><h2 id="dialog-title">${e(row.title)}</h2><div class="indicator">${e(row.value)}</div><p>${e(row.description||row.excerpt)}</p><h3>Defensive consideration</h3><p>${e(row.action)}</p><dl><dt>${row.source==='cisa-kev'?'Catalog added':'Source published'}</dt><dd>${e(date(row.published_at))}</dd>${row.first_seen?`<dt>First collected</dt><dd>${e(time(row.first_seen))}</dd>`:''}</dl>${link(row.source_url,'Original source','link')}`;
  if(!dialog.open)dialog.showModal();else document.querySelector('.dialog-close').focus();
}

function stixDetail(id) {
  const row=data.stix.objects.find(r=>r.id===id);if(!row)return;
  const lookup=new Map(data.stix.objects.map(o=>[o.id,o]));
  const edges=data.stix.relationships.filter(r=>r.source_ref===id||r.target_ref===id);
  document.querySelector('#dialog-content').innerHTML=`<div class="source-line">MITRE ATT&CK® · ${e(types[row.type]||row.type)} · ${e(row.external_id)}</div><h2 id="dialog-title">${e(row.name)}</h2>${row.tactics.length?`<p>Tactics: ${row.tactics.map(e).join(', ')}</p>`:''}<p class="source-line">Catalog modified ${e(date(row.modified))}</p>${link(row.url,'ATT&CK reference','link')}<h3>Source relationships</h3>${edges.length?`<ul class="relationship-list">${edges.map(edge=>{
    const source=lookup.get(edge.source_ref),target=lookup.get(edge.target_ref);
    return `<li><button class="link" data-stix="${e(source.id)}">${e(source.name)}</button> ${e(edge.relationship_type.replaceAll('-',' '))} <button class="link" data-stix="${e(target.id)}">${e(target.name)}</button><small>${e(edge.id)} · ${e(date(edge.modified))}</small></li>`;
  }).join('')}</ul>`:empty('No resolved source relationships in this bounded sample.')}<p class="source-line">Knowledge-base context; not a claim of recent activity.</p>`;
  if(!dialog.open)dialog.showModal();else document.querySelector('.dialog-close').focus();
}

function search() {
  const query=document.querySelector('#global-search').value.trim();
  const region=document.querySelector('#search-results');if(!region)return;
  if(!query){region.hidden=true;return;}
  const hits=[...groupStories(data.news),...data.records,...data.stix.objects].filter(row=>matches(row,query));
  region.hidden=false;
  region.innerHTML=`<div class="section-head"><h2>${hits.length} search results</h2><button class="link" data-clear-search>Clear search</button></div>${hits.length?`<ul>${hits.slice(0,40).map(row=>`<li><small>${e(row.type?'MITRE ATT&CK®':names[row.source])} ${e(row.external_id||row.value||date(row.published_at))}</small>${row.type?`<button class="link" data-stix="${e(row.id)}">${e(row.name)} ↗</button>`:row.kind?`<button class="link" data-evidence="${e(row.id)}">${e(row.title)} ↗</button>`:link(row.source_url,row.title)}</li>`).join('')}</ul>${hits.length>40?'<p class="source-line">First 40 results. Refine your search to narrow the list.</p>':''}`:empty('No matching intelligence.')}`;
}

function anchor() {
  const legacy={overview:'brief',briefings:'archive',sources:'brief'};
  const raw=location.hash.slice(1).split('?')[0];const id=legacy[raw]||raw;
  if(raw==='search'){
    document.querySelector('#global-search').value=new URLSearchParams(location.hash.split('?')[1]||'').get('q')||'';search();return;
  }
  const target=document.getElementById(id);if(!target)return;
  if(target.tagName==='DETAILS')target.open=true;
  target.scrollIntoView({block:'start'});
}

function click(event) {
  const button=event.target.closest('button');if(!button||!data)return;
  if(button.dataset.evidence)evidence(button.dataset.evidence);
  if(button.dataset.stix)stixDetail(button.dataset.stix);
  if(button.dataset.period){period=Number(button.dataset.period);document.querySelectorAll('[data-period]').forEach(b=>b.setAttribute('aria-pressed',Number(b.dataset.period)===period));trend();}
  if(button.dataset.newsFilter){newsFilter=button.dataset.newsFilter;newsLimit=6;document.querySelectorAll('[data-news-filter]').forEach(b=>b.setAttribute('aria-pressed',b.dataset.newsFilter===newsFilter));news();}
  if(button.hasAttribute('data-more-news')){const before=newsLimit;newsLimit+=6;news();document.querySelectorAll('.story')[before]?.querySelector('a')?.focus();}
  if(button.hasAttribute('data-more-catalog')){const before=catalogLimit;catalogLimit+=12;catalog();document.querySelectorAll('.catalog-item')[before]?.focus();}
  if(button.dataset.page){cvePage+=Number(button.dataset.page);cveRows();document.querySelector('[data-page]:not(:disabled)')?.focus();}
  if(button.hasAttribute('data-clear-search')){document.querySelector('#global-search').value='';search();document.querySelector('#global-search').focus();}
}
main.addEventListener('click',click);dialog.addEventListener('click',click);
main.addEventListener('input',event=>{
  if(event.target.id==='cve-search'){cveQuery=event.target.value;cvePage=0;cveRows();}
  if(event.target.id==='catalog-search'){catalogQuery=event.target.value;catalogLimit=12;catalog();}
});
main.addEventListener('change',event=>{
  if(event.target.id==='catalog-type'){catalogType=event.target.value;catalogLimit=12;catalog();}
  if(event.target.id==='archive-select'){const report=archives().find(r=>r.id===event.target.value);if(report)document.querySelector('#archived-report').innerHTML=report.input?editionMarkup(report):reportMarkup(report);}
});
document.querySelector('#search-form').addEventListener('submit',event=>{event.preventDefault();if(data){search();document.querySelector('#search-results')?.scrollIntoView({block:'start'});}});
document.querySelector('#global-search').addEventListener('input',event=>{if(data&&!event.target.value)search();});
document.querySelector('.dialog-close').addEventListener('click',()=>dialog.close());
window.addEventListener('hashchange',()=>{if(data)anchor();});
document.querySelector('nav').addEventListener('click',event=>{const a=event.target.closest('a');if(a&&a.hash===location.hash)anchor();});
try {
  const response=await fetch('./snapshot.json',{cache:'no-cache'});if(!response.ok)throw new Error();data=await response.json();
  if(![1,2,3,4].includes(data.schema_version)||typeof data.synthetic!=='boolean'||!['records','news','reports','sources'].every(k=>Array.isArray(data[k])))throw new Error();
  data.stix ||= {objects:[],relationships:[],status:'unavailable',collected_at:null};
  render();if(location.hash)anchor();
} catch {
  data=null;document.querySelector('#last-updated').textContent='Data unavailable';main.innerHTML='<h1>Intelligence unavailable</h1><p class="empty">The public data file could not be loaded. Refresh to retry.</p>';
}
