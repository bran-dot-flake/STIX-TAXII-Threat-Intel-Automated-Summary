import test from 'node:test';
import assert from 'node:assert/strict';
import {metrics,dailyKev,kindCounts,matches,groupStories,briefDigest,editorialStories} from '../website/analytics.js';

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
test('editorial selection groups catalog bulletins without dropping source citations',()=>{
  const rows=[
    {id:'1',title:'Catalog update one',category:'Exploitation watch',published_at:'2026-11-10'},
    {id:'2',title:'Catalog update two',category:'Exploitation watch',published_at:'2026-11-09'},
    {id:'3',title:'Vendor advisory',category:'Security advisory',published_at:'2026-11-08'},
  ];
  const grouped=groupStories(rows);assert.equal(grouped.length,2);assert.equal(grouped[0].id,'1');assert.equal(grouped[0].related[0].id,'2');
});
test('daily digest selects distinct supported observations and catalog search includes external IDs',()=>{
  const row={kind:'vulnerability',value:'CVE-2026-0001'};
  assert.equal(briefDigest({mode:'ollama-extractive',items:[row,row,{...row,value:'CVE-2026-0002'}]}).length,2);
  assert.deepEqual(briefDigest({mode:'quiet-day',items:[]}),[]);
  assert(matches({name:'Command and Scripting Interpreter',external_id:'T1059',type:'attack-pattern'},'t1059'));
});

test('campaign digest groups by original event and keeps unrelated CVEs separate',()=>{
  const event='https://www.circl.lu/doc/misp/feed-osint/00000000-0000-4000-8000-000000000001.json';
  const items=[...Array.from({length:3},(_,i)=>({id:`c${i}`,kind:'vulnerability',value:`CVE-2026-${i}`,source_url:'https://www.cisa.gov/catalog'})),...Array.from({length:5},(_,i)=>({id:`i${i}`,kind:'sha256',value:`hash${i}`,source_url:event,title:'Campaign'}))];
  const topics=briefDigest({items});assert.equal(topics.length,4);assert.equal(topics.at(-1).records.length,5);
  items.at(-1).source_url=event.replace('000001.json','000002.json');
  assert.equal(briefDigest({items:items.slice(3)}).length,2);
});

test('front-page ranking prioritizes current source evidence over historical bulletins',()=>{
  const rows=[
    {id:'old',title:'Earlier KEV bulletin',category:'Exploitation watch',excerpt:'Known exploitation.',published_at:'2026-11-01T12:00:00Z'},
    {id:'new',title:'Current advisory',category:'Security advisory',excerpt:'The source describes a remote attack.',published_at:'2026-11-11T12:00:00Z'},
    {id:'significant',title:'Current detailed advisory',category:'Security advisory',excerpt:'An unauthenticated attacker could execute arbitrary code.',published_at:'2026-11-10T12:00:00Z'},
  ];
  const ranked=editorialStories(rows,'2026-11-11T18:00:00Z',['significant']);
  assert.deepEqual(ranked.map(r=>r.id),['significant','new','old']);
});
