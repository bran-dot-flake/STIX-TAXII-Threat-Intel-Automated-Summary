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
  return [item.title, item.name, item.external_id, item.value, item.kind, item.type, item.description, item.excerpt].filter(Boolean).join(' ').toLowerCase().includes(query.trim().toLowerCase());
}

export function groupStories(news) {
  const groups = new Map();
  for (const row of [...news].sort((a,b)=>b.published_at.localeCompare(a.published_at))) {
    const key = row.category === 'Exploitation watch' ? 'kev-catalog' : row.title.toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
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
