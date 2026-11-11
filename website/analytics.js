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
    briefs: snapshot.reports.length,
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
  return [item.title, item.value, item.kind, item.description, item.excerpt].filter(Boolean).join(' ').toLowerCase().includes(query.trim().toLowerCase());
}
