import test from 'node:test';
import assert from 'node:assert/strict';
import {metrics,dailyKev,kindCounts,matches} from '../website/analytics.js';

const records=[
  {source:'cisa-kev',kind:'vulnerability',value:'CVE-2026-0001',published_at:'2026-11-10',first_seen:'2026-11-11T10:00:00Z'},
  {source:'cisa-kev',kind:'vulnerability',value:'CVE-2026-0001',published_at:'2026-11-10',first_seen:'2026-11-11T10:00:00Z'},
  {source:'circl-osint',kind:'domain',value:'evil[.]com',first_seen:'2026-11-11T10:00:00Z'},
  {source:'circl-osint',kind:'domain',value:'evil[.]com',first_seen:'2026-11-01T10:00:00Z'},
];
test('metrics deduplicate values and distinguish source publication from collection',()=>{
  assert.deepEqual(metrics({records,news:[{published_at:'2026-11-11T09:00:00Z'},{published_at:'2026-11-12T09:00:00Z'}],reports:[]},'2026-11-11T12:00:00Z'),{kev:1,news24:1,iocs:1,newIocs:0,briefs:0,advisories:2});
});
test('daily catalog chart uses UTC dates, zero fills, and deduplicates CVEs',()=>{
  const rows=dailyKev(records,7,'2026-11-11T12:00:00Z');
  assert.equal(rows.length,7);assert.equal(rows[0].date,'2026-11-05');assert.equal(rows.at(-1).date,'2026-11-11');
  assert.equal(rows.reduce((sum,r)=>sum+r.count,0),1);assert.equal(rows.at(-2).count,1);
});
test('type chart totals are deterministic and not inflated by repeated observations',()=>{
  assert.deepEqual(kindCounts(records),[['vulnerability',1],['domain',1]]);
});
test('empty datasets and case insensitive search',()=>{
  assert.equal(metrics({records:[],news:[],reports:[]},'2026-11-11').iocs,0);
  assert.equal(dailyKev([],30,'2026-11-11').length,30);
  assert.equal(matches({title:'Vendor Remote Access',value:'CVE-2026-0001'},' cve-2026 '),true);
  assert.equal(matches({title:'Vendor'},'<script>'),false);
});
