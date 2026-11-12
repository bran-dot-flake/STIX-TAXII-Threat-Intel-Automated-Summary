// Deterministic display metrics. No model-generated numbers or inferred relations.
export function uniqueIndicators(records) {
  return new Set(records.filter(r => r.kind !== 'vulnerability').map(r => `${r.kind}|${r.value}`)).size;
}
export function metrics(snapshot, now) {
  const end = new Date(now).getTime();
  const recent = v => v && new Date(v).getTime() <= end && new Date(v).getTime() >= end - 86400000;
  const firstSeen = new Map();
  for (const r of snapshot.records.filter(r=>r.kind !== 'vulnerability')) {
    const key = `${r.kind}|${r.value}`;
    if (!firstSeen.has(key) || Date.parse(r.first_seen) < Date.parse(firstSeen.get(key))) firstSeen.set(key,r.first_seen);
  }
  return {
    kev: new Set(snapshot.records.filter(r => r.source === 'cisa-kev').map(r => r.value)).size,
    news24: snapshot.news.filter(r => recent(r.published_at)).length,
    iocs: uniqueIndicators(snapshot.records),
    newIocs: [...firstSeen.values()].filter(recent).length,
    briefs: snapshot.reports.length+(snapshot.editions||[]).length,
    advisories: snapshot.news.length,
  };
}
export function dailyKev(records, days, now) {
  const end = new Date(now); end.setUTCHours(0, 0, 0, 0);
  const rows = Array.from({length: days}, (_, index) => {
    const date = new Date(end.getTime() - (days - index - 1) * 86400000).toISOString().slice(0, 10);
    return {date, count: 0};
  });
  const byDate = new Map(rows.map(r => [r.date, r])); const seen = new Set();
  for (const r of records) {
    if (r.source !== 'cisa-kev' || seen.has(r.value) || !r.published_at) continue;
    const date = r.published_at.slice(0, 10);
    if (byDate.has(date)) { byDate.get(date).count++; seen.add(r.value); }
  }
  return rows;
}
export function kindCounts(records) {
  const unique = new Set(); const counts = {};
  for (const r of records) {
    const key = `${r.kind}|${r.value}`;
    if (unique.has(key)) continue;
    unique.add(key); counts[r.kind] = (counts[r.kind] || 0) + 1;
  }
  return Object.entries(counts).sort((a,b) => b[1] - a[1]);
}
export function matches(item, query) {
  // Normalize only for comparison; stored/displayed indicators stay defanged.
  const normalize=value=>value.toLowerCase().replaceAll('[.]','.').replaceAll('hxxps://','https://').replaceAll('hxxp://','http://');
  return normalize([item.title, item.name, item.external_id, item.value, item.kind, item.type, item.description, item.excerpt].filter(Boolean).join(' ')).includes(normalize(query.trim()));
}

export const publicationTime = edition => edition.published_at||edition.generated_at;

export function visibleHistory(snapshot) {
  return [...(snapshot.editions||[]).filter(e=>e.topics.length),...snapshot.reports.filter(r=>r.mode!=='quiet-day'&&(r.observations||r.items).length)]
    .sort((a,b)=>publicationTime(b).localeCompare(publicationTime(a)));
}

export function publicationView(snapshot) {
  const editions=(snapshot.editions||[]).filter(e=>e.topics.length&&e.publication_kind==='weekly').sort((a,b)=>Date.parse(publicationTime(b))-Date.parse(publicationTime(a)));
  return {primary:editions[0]||null,update:null};
}

export function featuredPublication(snapshot) {
  return publicationView(snapshot).primary;
}

export function weeklyPeriod(start,end) {
  if(!start||!end)return '';
  const a=new Date(start),b=new Date(end);
  const month=d=>d.toLocaleDateString('en-US',{month:'short',timeZone:'UTC'});
  if(a.getUTCFullYear()===b.getUTCFullYear()&&a.getUTCMonth()===b.getUTCMonth())return `${month(a)} ${a.getUTCDate()}–${b.getUTCDate()}, ${b.getUTCFullYear()}`;
  if(a.getUTCFullYear()===b.getUTCFullYear())return `${month(a)} ${a.getUTCDate()} – ${month(b)} ${b.getUTCDate()}, ${b.getUTCFullYear()}`;
  return `${month(a)} ${a.getUTCDate()}, ${a.getUTCFullYear()} – ${month(b)} ${b.getUTCDate()}, ${b.getUTCFullYear()}`;
}

export function reportingTrends(news,days,now) {
  const rows=dailyKev([],days,now).map(r=>({...r,categories:{}}));
  const byDate=new Map(rows.map(r=>[r.date,r]));const seen=new Set(),counts={};
  for(const row of news){
    if(seen.has(row.source_url)||!row.published_at||Date.parse(row.published_at)>Date.parse(now))continue;
    const day=byDate.get(row.published_at.slice(0,10));if(!day)continue;
    seen.add(row.source_url);
    const category=['Exploitation watch','Security advisory','Vulnerability research'].includes(row.category)?'Vulnerabilities':row.category;
    day.count++;day.categories[category]=(day.categories[category]||0)+1;counts[category]=(counts[category]||0)+1;
  }
  return {series:rows,categories:Object.entries(counts).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])),total:seen.size};
}

export function catalogEntries(objects) {
  const ids={'attack-pattern':/^T\d{4}(?:\.\d{3})?$/,'intrusion-set':/^G\d{4}$/,malware:/^S\d{4}$/,tool:/^S\d{4}$/};
  return objects.filter(row=>{
    if(!row||!(ids[row.type] instanceof RegExp)||!ids[row.type].test(row.external_id)||typeof row.name!=='string'||!row.name.trim()||typeof row.id!=='string'||!new RegExp('^'+row.type+'--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$').test(row.id))return false;
    try{const url=new URL(row.url);return url.protocol==='https:'&&url.hostname==='attack.mitre.org'&&!url.username&&!url.password&&['','443'].includes(url.port);}catch{return false;}
  });
}

export function chartRows(series,showAll=false) {
  return showAll?series:series.filter(row=>row.count>0);
}

export function searchResults(snapshot,query) {
  if(!query.trim())return [];
  const observations=[...snapshot.records,...snapshot.reports.flatMap(r=>r.observations||r.items),...(snapshot.editions||[]).flatMap(editionEvidence)];
  const groups=new Map();
  const add=(key,row,type,label,title)=>{
    if(!groups.has(key))groups.set(key,{key,type,label,title,variants:new Map()});
    const variants=groups.get(key).variants;
    if(!variants.has(row.id))variants.set(row.id,[]);
    variants.get(row.id).push(row);
  };
  for(const row of observations){
    if(!row.kind)continue;
    if(row.kind==='vulnerability')add('cve:'+row.value.toUpperCase(),row,'vulnerability','Vulnerability',row.title);
    else if(row.source==='circl-osint'&&/^https:\/\/www\.circl\.lu\/doc\/misp\/feed-osint\/[0-9a-f-]{36}\.json$/.test(row.source_url))add('report:'+row.source_url,row,'report','Intelligence report',row.title);
    else add('indicator:'+row.id,row,'indicator','Indicator',row.title);
  }
  for(const row of [...snapshot.news,...(snapshot.editions||[]).flatMap(e=>e.input.news)])add('article:'+row.source_url,row,'advisory',row.source==='cisa-advisories'?'Security advisory':'Research report',row.title);
  const labels={'attack-pattern':'ATT&CK technique','intrusion-set':'Threat actor',malware:'Malware',tool:'Tool'};
  for(const row of catalogEntries(snapshot.stix?.objects||[]))add('stix:'+row.id,row,'stix',labels[row.type],row.name);
  const results=[];
  for(const group of groups.values()){
    const records=[...group.variants.values()].map(versions=>versions[0]);
    const matching=[...group.variants.values()].map(versions=>versions.find(row=>matches(row,query))).filter(Boolean);
    if(!matching.length)continue;
    // Multiple source versions of one CVE remain one result. Exact historical
    // matches open their actual evidence rather than an unrelated latest value.
    results.push({key:group.key,type:group.type,label:group.label,title:group.title,record:matching[0],records,matching});
  }
  return results;
}

export function groupStories(news) {
  const groups = new Map();
  for (const row of [...news].sort((a,b)=>b.published_at.localeCompare(a.published_at))) {
    const key = row.category === 'Exploitation watch' ? 'kev-catalog' : row.source_url||row.id;
    if (!groups.has(key)) groups.set(key,{...row,related:[]});
    else groups.get(key).related.push(row);
  }
  return [...groups.values()];
}

export function editorialStories(news, asOf, selectedIds=[]) {
  const end=Date.parse(asOf);
  const start=new Date(end);start.setUTCDate(start.getUTCDate()-1);start.setUTCHours(0,0,0,0);
  const selected=new Set(selectedIds);
  const rank=row=>{
    const stamp=Date.parse(row.published_at);
    const current=stamp>=start.getTime()&&stamp<=end;
    const supported=row.category==='Exploitation watch'?2:/unauthenticated|execute arbitrary code/i.test(row.excerpt)?1:0;
    return [current?1:0,selected.has(row.id)?1:0,supported,stamp];
  };
  return groupStories(news).sort((a,b)=>{
    const left=rank(a),right=rank(b);
    for(let i=0;i<left.length;i++)if(left[i]!==right[i])return right[i]-left[i];
    return a.id.localeCompare(b.id);
  });
}

// Reader presentation only. Original URLs, evidence and editorial plans stay intact.
export function editionEvidence(edition) {
  const rows=new Map();
  for(const row of [...edition.input.records,...edition.input.news])rows.set(row.id,{...row});
  for(const update of edition.input.updates){
    const original=rows.get(update.id);
    rows.set(update.id,{...original,...update,...(original?.description?{description:original.description}:{})});
  }
  return [...rows.values()];
}

export function isRawSource(url) {
  try{return /\.(?:json|csv|xml)$/i.test(new URL(url).pathname);}catch{return true;}
}

export function readerTarget(row) {
  try {
    const url=new URL(row.source_url);
    const approved=(row.source==='cisa-advisories'&&url.hostname==='www.cisa.gov'&&url.pathname.startsWith('/news-events/'))||(row.source==='sans-isc'&&url.hostname==='isc.sans.edu')||(row.source==='cisco-talos'&&url.hostname==='blog.talosintelligence.com')||(row.source==='google-gti'&&url.hostname==='cloud.google.com'&&url.pathname.startsWith('/blog/topics/threat-intelligence/'));
    if(approved&&url.protocol==='https:'&&!url.username&&!url.password&&!url.search&&!url.hash&&['','443'].includes(url.port)&&!isRawSource(url.href))return {kind:'article',url:row.source_url,id:row.id};
  }catch{}
  return {kind:'detail',id:row.id};
}

export function evidenceGroups(rows,topics=[]) {
  const lookup=new Map(rows.map(r=>[r.id,r]));const seen=new Set(),contexts=new Set(),groups=[];
  const append=(label,members)=>{
    if(!members.length)return;
    const unit=members.every(r=>r.kind==='vulnerability')?'CVE':members.every(r=>!r.kind)?'source report':members.every(r=>r.kind&&r.kind!=='vulnerability')?'indicator':'record';
    groups.push({key:`evidence-${members[0].id}`,label,unit,records:members,context_ids:[]});
    members.forEach(r=>seen.add(r.id));
  };
  for(const topic of topics){
    const ids=topic.evidence_ids||topic.supporting_evidence_ids||topic.records?.map(r=>r.id)||[];
    const members=[...new Set(ids)].map(id=>lookup.get(id)).filter(row=>row&&!seen.has(row.id));
    if(topic.kind==='catalog'){
      append('CISA KEV additions',members.filter(r=>r.kind==='vulnerability'));
      const articles=members.filter(r=>r.source==='cisa-advisories');
      append(articles.length===1?'CISA announcement':'CISA announcements',articles);
      append(topic.headline,members.filter(r=>!seen.has(r.id)));
    }else append(topic.headline||'Source evidence',members);
    const owner=groups.find(g=>g.records.some(r=>ids.includes(r.id)));
    if(owner)for(const id of topic.context_ids||[]){if(!contexts.has(id)){owner.context_ids.push(id);contexts.add(id);}}
  }
  append('Other source records',[...lookup.values()].filter(r=>!seen.has(r.id)));
  return groups;
}

export function usefulExcerpt(row) {
  const text=(row.excerpt||'').trim();
  if(!text||/^(?:source excerpt|no excerpt(?: available)?|excerpt unavailable|not available|n\/a)[.!]?$/i.test(text)||text.toLowerCase()===row.title?.trim().toLowerCase())return '';
  return text;
}

export function additionalStories(news,asOf,edition,category='all') {
  const categoryRows=news.filter(row=>category==='all'||row.category===category);
  if(!edition)return editorialStories(categoryRows,asOf);
  const ids=new Set(edition.topics.flatMap(t=>t.evidence_ids));
  const featured=editionEvidence(edition).filter(r=>ids.has(r.id));
  const articles=featured.filter(r=>!r.kind);
  const articleIds=new Set(articles.map(r=>r.id)),urls=new Set(articles.map(r=>r.source_url).filter(Boolean));
  const cves=new Set(featured.filter(r=>r.kind==='vulnerability').map(r=>r.value.toUpperCase()));
  const catalog=edition.topics.some(t=>t.kind==='catalog');
  // Filter originals before grouping so a featured bulletin cannot hide distinct
  // older reports inside its related-updates list. CVE overlap alone never removes a report.
  const distinct=categoryRows.filter(r=>!articleIds.has(r.id)&&!urls.has(r.source_url));
  const end=Date.parse(asOf),start=new Date(end);start.setUTCDate(start.getUTCDate()-1);start.setUTCHours(0,0,0,0);
  const current=row=>Date.parse(row.published_at)>=start.getTime()&&Date.parse(row.published_at)<=end;
  const related=row=>(catalog&&row.category==='Exploitation watch')||(row.title+' '+row.excerpt).match(/CVE-\d{4}-\d{4,7}/gi)?.some(id=>cves.has(id.toUpperCase()));
  return editorialStories(distinct,asOf).sort((a,b)=>Number(current(b))-Number(current(a))||Number(Boolean(related(a)))-Number(Boolean(related(b))));
}

export function briefDigest(report) {
  if (!report || report.mode === 'quiet-day') return [];
  const rows=report.observations||report.items;
  if(report.narrative)return report.narrative.plan.topics.map(topic=>({...topic,records:rows.filter(r=>topic.supporting_evidence_ids.includes(r.id))}));
  const groups=new Map();
  for(const row of rows){
    const event=/^https:\/\/www\.circl\.lu\/doc\/misp\/feed-osint\/[0-9a-f-]{36}\.json$/.test(row.source_url||'');
    const key=row.kind==='vulnerability'?`cve:${row.value}`:event?row.source_url:`observation:${row.id}`;
    if(!groups.has(key))groups.set(key,{headline:row.title||row.value,summary:[],why_it_matters:null,freshness:'historical-context',records:[]});
    groups.get(key).records.push(row);
  }
  return [...groups.values()].slice(0,4);
}
