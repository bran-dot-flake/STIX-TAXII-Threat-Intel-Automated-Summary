import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ti_brief.feeds import KEV
from ti_brief.model import Record
from ti_brief.publication import (NEWS, attach_briefs, circl_public_records, clean_text, clear_marking, collect_public,
    empty_snapshot, news_items, project_record, public_value, save_snapshot, source_url, validate_snapshot)
from ti_brief.publish import publish
from ti_brief.report import evidence_digest

NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)
RECORD = Record(source="CISA KEV", source_url=KEV, kind="vulnerability", value="CVE-2026-12345",
    title="Example vulnerability", description="A source-reported vulnerability.", published_at="2026-11-10", priority=90)


def fixture():
    value = empty_snapshot()
    value.update(collected_at=NOW.isoformat(), exported_at=NOW.isoformat(), records=[project_record(RECORD,"cisa-kev",NOW.isoformat())])
    return value


class PublicationTests(unittest.TestCase):
    def test_public_markings_fail_closed(self):
        self.assertFalse(clear_marking({}))
        self.assertTrue(clear_marking({"Tag":[{"name":"tlp:clear"}]}))
        for node in [
            {"Tag":[{"name":"tlp:white"},{"name":"tlp:amber+strict"}]},
            {"Tag":[{"name":"tlp:clear"}],"distribution":"0"},
            {"Tag":[{"name":"tlp:clear"}],"distribution":"5"},
            {"Tag":[{"name":"tlp:clear"}],"sharing_group_id":"7"},
            {"Tag":[{"name":"tlp:clear"},{"name":"pap:red"}]},
        ]:
            self.assertFalse(clear_marking(node))
        self.assertFalse(clear_marking({"Tag":[{"name":"tlp:green"}]},True))
        self.assertTrue(clear_marking({"distribution":"5"},True))

    def test_internal_addresses_and_credentials_rejected(self):
        for kind,value in [('ip-dst','10.20.0.1'),('ip-dst','127.0.0.1'),('ip-dst','::1'),
            ('ip-dst','192.0.2.25'),('ip-dst','224.0.0.1'),('ip-dst','ff02::1'),('domain','server.local'),('domain','server.corp'),('domain','localhost'),('url','http://10.0.0.1/path'),
            ('url','https://user:password@evil.example.com'),('url','https://evil.example.com/?api_key=secret')]:
            with self.assertRaises(ValueError, msg=value): public_value(kind,value)
        self.assertEqual(public_value('ip-dst','8.8.8.8'),'8[.]8[.]8[.]8')
        for text in ['Contact lab 10.0.0.1', 'Contact lab 10[.]0[.]0[.]1', 'See fd00::1', 'token=abc', 'TLP:AMBER', 'server.internal', 'x@y.com']:
            with self.assertRaises(ValueError, msg=text): clean_text(text)

    def test_circl_adapter_checks_event_object_and_attribute_restrictions(self):
        uid='00000000-0000-4000-8000-000000000001'
        event={'published':True,'info':'Public test evidence','publish_timestamp':str(int(NOW.timestamp())),
            'Tag':[{'name':'tlp:clear'}],
            'Attribute':[{'type':'ip-dst','value':'8.8.8.8'},
                         {'type':'ip-dst','value':'1.1.1.1','Tag':[{'name':'tlp:red'}]},
                         {'type':'ip-dst','value':'10.0.0.1'}],
            'Object':[{'Tag':[{'name':'tlp:amber'}],'Attribute':[{'type':'ip-dst','value':'9.9.9.9'}]}]}
        class Source:
            def json(self,url):
                return {uid:{'timestamp':str(int(NOW.timestamp()))}} if url.endswith('manifest.json') else {'Event':event}
        self.assertEqual([r.value for r in circl_public_records(Source(),NOW)],['8.8.8.8'])
        event['Tag']=[{'name':'tlp:green'}]
        self.assertEqual(circl_public_records(Source(),NOW),[])

    def test_urls_and_schema_are_allowlisted(self):
        for url in ['http://www.cisa.gov/news-events/x','https://evil.com/news-events/x','https://www.cisa.gov@evil.com/news-events/x','https://www.cisa.gov/news-events/x?token=secret']:
            with self.assertRaises(ValueError): source_url(url,'cisa-advisories')
        value=fixture(); validate_snapshot(value)
        for target,field in [('root','platform_context'),('record','misp_uuid')]:
            changed=copy.deepcopy(value)
            (changed if target=='root' else changed['records'][0])[field]='private'
            with self.assertRaises(ValueError): validate_snapshot(changed)
        changed=copy.deepcopy(value); changed['synthetic']=True
        with self.assertRaises(ValueError): validate_snapshot(changed)

    def test_news_strips_html_and_blocks_entities(self):
        raw='''<rss><channel><item><title>Security advisory</title><link>https://www.cisa.gov/news-events/alerts/example</link><pubDate>Tue, 10 Nov 2026 12:00:00 +0000</pubDate><description>&lt;p&gt;Safe text&lt;/p&gt;&lt;script&gt;steal()&lt;/script&gt;</description></item></channel></rss>'''
        rows=news_items(raw,NOW)
        self.assertEqual(len(rows),1); self.assertEqual(rows[0]['excerpt'],'Safe text')
        with self.assertRaises(ValueError): news_items('<!DOCTYPE rss [<!ENTITY e "x">]><rss/>',NOW)
        self.assertEqual(news_items(raw.replace('www.cisa.gov','evil.com'),NOW),[])

    def test_source_failure_keeps_previous_valid_data_and_dates(self):
        value=fixture(); value['sources']=[{'id':'cisa-kev','status':'ok','attempted_at':NOW.isoformat(),'last_success_at':NOW.isoformat()}]
        class Broken:
            def json(self,*args): raise RuntimeError('secret response')
            def request(self,*args): raise RuntimeError('secret response')
        with patch('builtins.print'):
            result, originals=collect_public(Broken(),value,NOW)
        self.assertEqual(result['records'],value['records']); self.assertEqual(originals,{})
        self.assertEqual(result['sources'][0]['status'],'cached')
        self.assertEqual(result['sources'][0]['last_success_at'],NOW.isoformat())

    def test_exact_brief_promotion_excludes_all_platform_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json'
            raw={'status':'complete','evidence_digest':evidence_digest([RECORD]),'records':[{'id':RECORD.key,'version':RECORD.version}],
                'selection':[{'record_id':RECORD.key,'excerpt':RECORD.title}], 'platform_context':{'MISP':'10.20.0.1','api_key':'secret'}}
            path.write_text(json.dumps(raw)); path.with_suffix('.md').write_text('Generated: 2026-11-11T10:00:00+00:00\nReport mode: Ollama selected, validated source excerpts.\nPRIVATE CONTENT')
            result=attach_briefs(fixture(),{RECORD.key:RECORD},directory)
            self.assertEqual(len(result['reports']),1)
            self.assertEqual(result['reports'][0]['mode'],'ollama-extractive')
            self.assertNotIn('10.20.0.1',json.dumps(result)); self.assertNotIn('secret',json.dumps(result)); self.assertNotIn('platform_context',json.dumps(result))
            raw['records'][0]['version']='changed'; path.write_text(json.dumps(raw))
            self.assertEqual(attach_briefs(fixture(),{RECORD.key:RECORD},directory)['reports'],[])
            raw['records'][0]['version']=RECORD.version; raw['selection'][0]['excerpt']='Invented fact'; path.write_text(json.dumps(raw))
            self.assertEqual(attach_briefs(fixture(),{RECORD.key:RECORD},directory)['reports'],[])

    def test_publisher_writes_only_safe_json_and_never_forces(self):
        calls=[]
        def api(endpoint,payload=None,method=None):
            calls.append((endpoint,payload,method))
            if '/branches?' in endpoint: return [{'name':'intel-data','commit':{'sha':'old'}}]
            if endpoint.endswith('/git/commits/old'): return {'tree':{'sha':'tree'}}
            if endpoint.endswith('/git/trees/tree'): return {'tree':[{'path':'snapshot.json'}]}
            return {'sha':'new'}
        self.assertEqual(publish(fixture(),'owner/repo',api),'new')
        trees=[p for u,p,m in calls if u.endswith('/git/trees')]
        self.assertEqual([r['path'] for r in trees[0]['tree']],['snapshot.json'])
        update=next(p for u,p,m in calls if m=='PATCH'); self.assertIs(update['force'],False)
        self.assertTrue(calls[-1][0].endswith('/pages.yml/dispatches'))
        bad=fixture(); bad['records'][0]['password']='secret'
        with self.assertRaises(ValueError): publish(bad,'owner/repo',api)

    def test_publisher_rejects_unexpected_branch_content(self):
        def api(endpoint,payload=None,method=None):
            if '/branches?' in endpoint: return [{'name':'intel-data','commit':{'sha':'old'}}]
            if '/commits/' in endpoint:return {'tree':{'sha':'tree'}}
            return {'tree':[{'path':'snapshot.json'},{'path':'.env'}]}
        with self.assertRaises(ValueError): publish(fixture(),'owner/repo',api)

    def test_quiet_day_and_demo_do_not_masquerade_as_llm_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'quiet.json'
            path.write_text(json.dumps({'status':'complete','records':[],'selection':[],'evidence_digest':evidence_digest([])}))
            path.with_suffix('.md').write_text('Generated: 2026-11-11T10:00:00+00:00\nReport mode: No new records.')
            result=attach_briefs(fixture(),{},directory)
            self.assertEqual(result['reports'],[])
        demo=json.loads((Path(__file__).resolve().parents[1]/'examples/dashboard.synthetic.json').read_text())
        validate_snapshot(demo,allow_synthetic=True)
        with self.assertRaises(ValueError): validate_snapshot(demo)
        with self.assertRaises(ValueError): publish(demo,'owner/repo')

    def test_build_refuses_unexpected_files_and_private_input(self):
        from scripts.build_dashboard import build
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'out'; output.mkdir(); (output/'private-report.md').write_text('secret')
            with self.assertRaises(ValueError): build(None,output)
            source=Path(directory)/'private.json'; source.write_text(json.dumps({'platform_context':'secret'}))
            with self.assertRaises(ValueError): build(source,Path(directory)/'safe-output')


if __name__=='__main__': unittest.main()
