import test from 'node:test';
import assert from 'node:assert/strict';
import {publicationView,visibleHistory,featuredPublication,weeklyPeriod,reportingTrends} from '../website/analytics.js';
import {metrics,dailyKev,kindCounts,matches,groupStories,briefDigest,editorialStories,editionEvidence,evidenceGroups,readerTarget,isRawSource,additionalStories,usefulExcerpt,searchResults,catalogEntries,chartRows} from '../website/analytics.js';

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

const articleURL='https://www.cisa.gov/news-events/alerts/2026/11/10/cisa-adds-six-known-exploited-vulnerabilities-catalog';
const machineURL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
function readerFixture(){
  const cves=Array.from({length:6},(_,i)=>({id:`c${i}`,source:'cisa-kev',source_url:machineURL,kind:'vulnerability',value:`CVE-2026-${10000+i}`,title:`Product ${i}`}));
  const article={id:'lead',source:'cisa-advisories',source_url:articleURL,title:'Catalog additions',excerpt:'CISA reports catalog additions.',category:'Exploitation watch',published_at:'2026-11-10T12:00:00Z'};
  return {input:{records:cves,news:[article],updates:[]},topics:[{id:'catalog',kind:'catalog',headline:'Catalog additions',evidence_ids:[...cves.map(r=>r.id),article.id]},{id:'detail',headline:'Specific product',evidence_ids:['c0'],context_ids:['technique-1']}]};
}
test('supporting evidence counts six CVEs and one announcement without repeating topic records',()=>{
  const edition=readerFixture(),rows=editionEvidence(edition),before=JSON.stringify(edition);
  const groups=evidenceGroups(rows,edition.topics);
  assert.deepEqual(groups.map(g=>[g.label,g.records.length,g.unit]),[['CISA KEV additions',6,'CVE'],['CISA announcement',1,'source report']]);
  assert.equal(groups.flatMap(g=>g.records).length,7);
  assert.deepEqual(groups[0].context_ids,['technique-1']);
  assert.equal(JSON.stringify(edition),before);
});
test('legacy indicators and ungrouped evidence retain their original records',()=>{
  const rows=[{id:'ioc1',kind:'sha256',value:'a'.repeat(64)},{id:'ioc2',kind:'url',value:'hxxps://evil[.]com'},{id:'other',kind:'domain',value:'other[.]com'}];
  const groups=evidenceGroups(rows,[{headline:'Original event',evidence_ids:['ioc1','ioc1','ioc2']}]);
  assert.equal(groups[0].records.length,2);assert.equal(groups[0].unit,'indicator');
  assert.deepEqual(groups.flatMap(g=>g.records.map(r=>r.id)),['ioc1','ioc2','other']);
});
test('reader destinations use explicit human advisory URLs and local CVE/IOC details',()=>{
  const edition=readerFixture();
  assert.deepEqual(readerTarget(edition.input.news[0]),{kind:'article',url:articleURL,id:'lead'});
  assert.deepEqual(readerTarget(edition.input.records[0]),{kind:'detail',id:'c0'});
  assert.deepEqual(readerTarget({id:'ioc',source:'circl-osint',source_url:'https://www.circl.lu/doc/misp/feed-osint/00000000-0000-4000-8000-000000000001.json'}),{kind:'detail',id:'ioc'});
  assert(isRawSource(machineURL));assert(!isRawSource(articleURL));
});
test('reader links cannot turn arbitrary URLs, credentials or raw feeds into human destinations',()=>{
  for(const url of ['javascript:alert(1)','https://www.cisa.gov@evil.com/news-events/x','https://www.cisa.gov:4444/news-events/x','https://www.cisa.gov/news-events/feed.json','https://www.cisa.gov/news-events/x?token=secret'])assert.equal(readerTarget({id:'row',source:'cisa-advisories',source_url:url}).kind,'detail');
});
test('homepage suppresses the exact featured article by stable ID or URL without deleting source data',()=>{
  const edition=readerFixture(),lead=edition.input.news[0];
  const other={...lead,id:'different',source_url:'https://www.cisa.gov/news-events/alerts/other',title:'Different product advisory',category:'Security advisory'};
  const news=[lead,{...lead,id:'same-url'},other],before=JSON.stringify(news);
  const stories=additionalStories(news,'2026-11-11T18:00:00Z',edition);
  assert.deepEqual(stories.map(r=>r.id),['different']);assert.equal(JSON.stringify(news),before);
});
test('related CVEs and older catalog bulletins remain available as distinct source reports',()=>{
  const edition=readerFixture(),lead=edition.input.news[0];
  const related={...lead,id:'related',source_url:'https://www.cisa.gov/news-events/alerts/new-guidance',title:'New guidance for CVE-2026-10000',category:'Security advisory'};
  const older={...lead,id:'older',source_url:'https://www.cisa.gov/news-events/alerts/older-catalog',title:'Earlier catalog additions',published_at:'2026-11-09T12:00:00Z'};
  const stories=additionalStories([lead,related,older],'2026-11-11T18:00:00Z',edition);
  assert.deepEqual(stories.map(r=>r.id),['related','older']);
  assert(stories.every(r=>r.related.every(child=>child.id!=='lead')));
});
test('quiet or absent editions do not hide distinct articles and empty evidence stays empty',()=>{
  const row=readerFixture().input.news[0];
  assert.equal(additionalStories([row],'2026-11-11T18:00:00Z').length,1);
  const edition=readerFixture();edition.topics=[];
  assert.equal(additionalStories([row],'2026-11-11T18:00:00Z',edition).length,1);
  assert.deepEqual(evidenceGroups([],[]),[]);
});
test('meaningful short excerpts survive while empty or placeholder previews are omitted',()=>{
  for(const excerpt of ['', '  ', 'Source excerpt','No excerpt available.','Not available','Headline'])assert.equal(usefulExcerpt({title:'Headline',excerpt}),'');
  assert.equal(usefulExcerpt({title:'Headline',excerpt:'Patch available.'}),'Patch available.');
});
test('source update dates remain accessible alongside the full original description',()=>{
  const edition=readerFixture();edition.input.records[0].description='Complete original source description.';
  edition.input.updates=[{...edition.input.records[0],excerpt:'Short excerpt.',modified_at:'2026-11-11T12:00:00Z',content_changed_at:'2026-11-11T12:30:00Z'}];
  const row=editionEvidence(edition).find(r=>r.id==='c0');
  assert.equal(row.description,'Complete original source description.');assert.equal(row.modified_at,'2026-11-11T12:00:00Z');
  assert.equal(editionEvidence(edition).length,7);
});

test('category metadata and optional filtering remain available without homepage controls',()=>{
  const lead=readerFixture().input.news[0],advisory={...lead,id:'advisory',title:'Product advisory',category:'Security advisory'};
  assert.deepEqual(additionalStories([lead,advisory],'2026-11-11T18:00:00Z',null,'Security advisory').map(r=>r.id),['advisory']);
  assert.equal(lead.category,'Exploitation watch');
});

const eventURL='https://www.circl.lu/doc/misp/feed-osint/00000000-0000-4000-8000-000000000001.json';
function searchFixture(){
  const indicators=[{id:'hash',source:'circl-osint',source_url:eventURL,title:'MoustachedBouncer',kind:'sha256',value:'a'.repeat(64)},{id:'url',source:'circl-osint',source_url:eventURL,title:'MoustachedBouncer',kind:'url',value:'hxxps://malicious[.]org/path'},{id:'ip',source:'circl-osint',source_url:eventURL,title:'MoustachedBouncer',kind:'ip-dst',value:'8[.]8[.]8[.]8'}];
  return {records:indicators,news:[],reports:[{items:[indicators[0]]}],editions:[{input:{records:indicators,news:[],updates:[]}}],stix:{objects:[]}};
}
test('global search groups one original report across records and archived datasets',()=>{
  const data=searchFixture(),before=JSON.stringify(data),hits=searchResults(data,'moustachedbouncer');
  assert.equal(hits.length,1);assert.equal(hits[0].type,'report');assert.equal(hits[0].records.length,3);assert.equal(hits[0].matching.length,3);
  assert.equal(JSON.stringify(data),before);
});
test('same-title reports with different original event IDs stay separate',()=>{
  const data=searchFixture();data.records.push({...data.records[0],id:'other',source_url:eventURL.replace('000001.json','000002.json')});
  assert.equal(searchResults(data,'MoustachedBouncer').length,2);
});
test('exact hashes, armed/defanged URLs, domains and IPs still find their original observation',()=>{
  const data=searchFixture();
  for(const [query,id] of [['a'.repeat(64),'hash'],['https://malicious.org/path','url'],['malicious.org','url'],['hxxps://malicious[.]org/path','url'],['8.8.8.8','ip']]){
    const hits=searchResults(data,query);assert.equal(hits.length,1);assert.deepEqual(hits[0].matching.map(r=>r.id),[id]);
  }
  assert.equal(data.records[1].value,'hxxps://malicious[.]org/path');
});
test('CVE and source article duplicates coalesce by identity, not matching title',()=>{
  const data=searchFixture(),row={id:'cve',kind:'vulnerability',value:'CVE-2026-10000',title:'Product flaw'};
  const article={id:'article',source:'cisa-advisories',source_url:articleURL,title:'Product advisory'};
  data.records.push(row);data.news.push(article);data.reports.push({items:[{...row,id:'other-cve'}]});data.editions[0].input.news.push({...article,id:'archived-article'});
  assert.equal(searchResults(data,'CVE-2026-10000').length,1);
  assert.equal(searchResults(data,'Product advisory').length,1);
  data.news.push({...article,id:'distinct',source_url:articleURL+'/different'});
  assert.equal(searchResults(data,'Product advisory').length,2);
});
test('historical exact matches retain their own evidence version',()=>{
  const data=searchFixture();data.reports.push({items:[{id:'older',kind:'vulnerability',value:'CVE-2026-10000',title:'Earlier source title'}]});
  data.records.push({id:'current',kind:'vulnerability',value:'CVE-2026-10000',title:'Current source title'});
  assert.equal(searchResults(data,'Earlier source title')[0].record.id,'older');
  assert.equal(searchResults(data,'CVE-2026-10000').length,1);
});
const technique={id:'attack-pattern--00000000-0000-4000-8000-000000000001',type:'attack-pattern',external_id:'T1059',name:'Command and Scripting Interpreter',url:'https://attack.mitre.org/techniques/T1059/',tactics:[]};
test('catalog cards exclude blank or malformed identity fields without invented placeholders',()=>{
  const objects=[technique,null,{...technique,name:'  '},{...technique,name:23},{...technique,type:'unknown'},{...technique,external_id:''},{...technique,id:'attack-pattern--bad-id'},{...technique,url:'https://evil.com/'}];
  assert.deepEqual(catalogEntries(objects),[technique]);
});
test('ATT&CK identifiers remain searchable with explicit source types',()=>{
  const data=searchFixture();data.stix.objects=[technique];
  const hit=searchResults(data,'T1059')[0];assert.equal(hit.type,'stix');assert.equal(hit.label,'ATT&CK technique');assert.equal(hit.record.external_id,'T1059');
  assert.deepEqual(searchResults(data,'   '),[]);
});
test('condensed chart tables preserve full dates and totals behind the all-days option',()=>{
  const series=dailyKev(records,30,'2026-11-11T12:00:00Z');
  const compact=chartRows(series);assert(compact.every(r=>r.count>0));assert.equal(chartRows(series,true).length,30);
  assert.equal(compact.reduce((n,r)=>n+r.count,0),series.reduce((n,r)=>n+r.count,0));
  assert.deepEqual(chartRows(dailyKev([],7,'2026-11-11')),[]);assert.equal(chartRows(dailyKev([],7,'2026-11-11'),true).length,7);
});


test('quiet collections keep the substantive weekly date and hide quiet archive entries',()=>{
  const weekly={id:'w',publication_kind:'weekly',generated_at:'2026-11-09T08:05:00Z',topics:[{evidence_ids:[]}],input:{records:[],news:[],updates:[]}};
  const quiet={id:'q',generated_at:'2026-11-12T08:05:00Z',topics:[]};
  const snapshot={editions:[quiet,weekly],reports:[{mode:'quiet-day',generated_at:'2026-11-12T08:00:00Z',items:[]}]};
  assert.equal(publicationView(snapshot).primary,weekly);assert.equal(publicationView(snapshot).update,null);
  assert.deepEqual(visibleHistory(snapshot),[weekly]);assert.equal(publicationView(snapshot).primary.generated_at,'2026-11-09T08:05:00Z');
});
test('legacy interim stays in the archive but never replaces or expands the weekly article',()=>{
  const weekly={id:'w',publication_kind:'weekly',generated_at:'2026-11-09T08:05:00Z',topics:[{evidence_ids:['a']}],input:{records:[],news:[{id:'a',source_url:'https://isc.sans.edu/a'}],updates:[]}};
  const update={id:'u',publication_kind:'update',generated_at:'2026-11-12T08:05:00Z',topics:[{evidence_ids:['b']}],input:{records:[],news:[{id:'b',source_url:'https://isc.sans.edu/b'}],updates:[]}};
  const snapshot={editions:[update,weekly],reports:[]};
  assert.equal(publicationView(snapshot).primary,weekly);assert.equal(publicationView(snapshot).update,null);
  assert.equal(featuredPublication(snapshot).input.news.length,1);assert.equal(visibleHistory(snapshot).length,2);
});
test('initial publication state and legacy substantive history remain usable',()=>{
  assert.deepEqual(publicationView({editions:[],reports:[]}),{primary:null,update:null});
  const old={id:'old',generated_at:'2026-11-10',topics:[{}]};
  assert.equal(publicationView({editions:[old],reports:[]}).primary,null);assert.deepEqual(visibleHistory({editions:[old],reports:[]}),[old]);
});
test('reporting trends count unique original reports, UTC dates and subjects, not attacks',()=>{
  const rows=[{source_url:'https://isc.sans.edu/a',category:'Malware research',published_at:'2026-11-10T12:00:00Z'},
    {source_url:'https://isc.sans.edu/a',category:'Malware research',published_at:'2026-11-10T12:00:00Z'},
    {source_url:'https://blog.talosintelligence.com/b',category:'Phishing',published_at:'2026-11-11T12:00:00Z'},
    {source_url:'https://www.cisa.gov/c',category:'Exploitation watch',published_at:'2026-11-12T09:00:00Z'},
    {source_url:'https://isc.sans.edu/future',category:'Malware research',published_at:'2026-11-12T14:00:00Z'},
    {source_url:'https://isc.sans.edu/old',category:'Campaign reporting',published_at:'2025-01-01T00:00:00Z'}];
  const result=reportingTrends(rows,7,'2026-11-12T12:00:00Z');
  assert.equal(result.total,3);assert.equal(result.series.length,7);
  assert.equal(result.series.reduce((n,r)=>n+r.count,0),3);
  assert.deepEqual(Object.fromEntries(result.categories),{'Malware research':1,Phishing:1,Vulnerabilities:1});
  assert.equal(reportingTrends(rows,30,'2026-11-12T12:00:00Z').series.length,30);
});
test('same-title research reports keep independent source identities',()=>{
  const rows=['one','two'].map((id)=>({id,title:'Same actor campaign',category:'Campaign reporting',published_at:'2026-11-11',source_url:'https://isc.sans.edu/'+id}));
  assert.equal(groupStories(rows).length,2);
});
test('research readers only open the matching official publisher',()=>{
  for(const [source,url] of [['sans-isc','https://isc.sans.edu/diary/123/'],['cisco-talos','https://blog.talosintelligence.com/research/'],['google-gti','https://cloud.google.com/blog/topics/threat-intelligence/report/']])assert.equal(readerTarget({id:'x',source,source_url:url}).kind,'article');
  assert.equal(readerTarget({id:'x',source:'google-gti',source_url:'https://cloud.google.com/private/'}).kind,'detail');
  assert.equal(readerTarget({id:'x',source:'sans-isc',source_url:'https://evil.com/diary/123/'}).kind,'detail');
});

test('weekly periods use concise UTC dates across month and year boundaries',()=>{
  assert.equal(weeklyPeriod('2026-11-02T08:00:00Z','2026-11-09T08:00:00Z'),'Nov 2–9, 2026');
  assert.equal(weeklyPeriod('2026-10-26T08:00:00Z','2026-11-02T08:00:00Z'),'Oct 26 – Nov 2, 2026');
  assert.equal(weeklyPeriod('2026-12-28T08:00:00Z','2027-01-04T08:00:00Z'),'Dec 28, 2026 – Jan 4, 2027');
});
