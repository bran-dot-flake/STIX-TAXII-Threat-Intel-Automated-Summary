# Public publication contract and operations

`scripts/export_publication.py` independently recollects original public sources and optionally publishes through existing `gh` authentication. It does not call platform APIs or Ollama. The staged scheduler invokes it when `TI_PUBLICATION_ENABLED=true`, including after backend failures. All existing private reporting paths remain available.

## Schema version 6 (versions 1–5 remain readable)

`src/ti_brief/publication.py:validate_snapshot` is the executable contract. Unknown object keys are rejected. The live validator rejects synthetic data; only explicit `build_dashboard.py --demo` permits the labeled fixture.

| Object | Exact fields |
| --- | --- |
| Snapshot | `schema_version` (6), `synthetic`, `collected_at`, `exported_at`, `sources`, `records`, `news`, `reports`, `stix`, `editions`, `collection` |
| Collection | `checked_at`, `status` (`ready`, `quiet`, `source-failure`, `published`, `withheld`), `last_substantive_at`, `weekly_window_end` |
| Source health | `id`, `status` (`ok`, `cached`, `unavailable`), `attempted_at`, `last_success_at` |
| Observation | `id`, `source`, `source_url`, `kind`, `value`, `title`, `description`, `action`, `published_at`, `first_seen`, `last_seen` |
| News | `id`, `source`, `source_url`, `title`, `excerpt`, `published_at`, `category`, `artwork` |
| Brief | `id`, `generated_at`, `mode` (`ollama-extractive`, `deterministic`, `quiet-day`), `evidence_count`, `items`, `observations`, `narrative` |
| Brief item | `id`, `excerpt`, `title`, `source`, `source_url`, `value`, `kind`, `action`, `published_at` |

Brief `observations` retain all independently matched source records, even those omitted by the excerpt selector. They contain the brief-item fields plus `modified_at`, `first_seen`, `last_seen`, `content_changed_at`, and `known_content_change`. Collection/change metadata is typed and bounded by generation time; all source fields are rederived from original records. Legacy editions retain unknown chronology rather than assigning today’s collection dates.

`narrative` contains exactly `version`, `mode` (`ollama-grounded` or `deterministic-fallback`), `composed_at`, `input_digest`, `window_start`, `window_end`, and `plan`. The plan contains overview claims and up to four topics with claim/text pairs, headline, freshness, significance, and supporting evidence IDs. Its complete content is independently checked against the recomputed fact ledger, not trusted because the model supplied IDs. [Exact narrative contract](briefing.md).

Limits: 5,000 observations, 240 retained news records, ninety accepted editions, eight source observations per brief, 240 characters per validated brief excerpt, and forty-five words per CISA news excerpt / eighty words per research-feed excerpt. Evidence IDs are 24-character hashes. Indicator values are canonicalized and defanged. Source IDs are `cisa-kev`, `circl-osint`, `cisa-advisories`, `sans-isc`, `cisco-talos` and `google-gti`. Legacy artwork metadata remains accepted; the frontend uses at most one original advisory illustration in the visible grid.

The `stix` object contains exactly `source`, `collected_at`, `status`, `objects`, `relationships`, `counts`, and `license`. Only `mitre-enterprise` is publishable. Up to 160 named objects expose `id`, `type`, `name`, `external_id`, `url`, `modified`, and `tactics`. Up to sixty resolved relationships expose original `id`, `source_ref`, `target_ref`, `relationship_type`, and `modified`. Counts must exactly equal published node types. Unknown keys, private links, unresolved endpoints, unsupported identities, and unreviewed licenses are rejected. [STIX policy](stix-taxii.md).

Timestamps are ISO 8601 UTC; source date-only values display as midnight UTC. `published_at` can be null when unknown. `first_seen` means first collection by this publication, not source discovery or incident occurrence. Initial IOC counts form a bootstrap baseline. Catalog dates specifically mean KEV `dateAdded`.

`collected_at` is the latest successful adapter fetch, not proof all adapters succeeded. Each source retains its own success time. `exported_at` is sanitized snapshot creation; briefs carry their own generation time. The builder creates a separate `build.json`. Build time is explicitly distinguished from deployment completion, which is recorded in the linked public Actions log.

`editions` retains up to ninety accepted substantive articles, separately from original batch reports. Version-2 hybrid editions contain `version`, `id`, `publication_kind` (`weekly` or `update`), `generated_at`, `published_at`, `window_start`, `window_end`, `input_digest`, `input`, `topics`, `plan`, `mode` and `story_versions`. Their input has the existing public source/record/news/update/context fields plus `publication_kind`, `window_start`, `window_end` and `covered_story_ids`. Up to 36 records, four articles, six source-health records and eight explicit catalog references are allowed. Topics add a checked `previously_reported` flag. Source prose, grouping, windows, continuity hashes and output are recomputed and checked; historical accepted inputs are immutable. Version-1 daily editions retain their historical validator. [Selection, timing and grounding](briefing.md).

`collection` records the latest check independently of the latest substantive article. Quiet collections update data but create no article. New zero-record private batches are not promoted publicly; historical quiet entries remain readable input. `generated_at` is the fixed evidence cutoff; `published_at` is the publication timestamp set at successful upload, which can be on a later UTC date. Cached unpublished candidates have no publication date and cannot be public snapshots. The public data commit must succeed before local accepted editorial state advances. A failed Pages dispatch after a successful data commit is reported separately and does not rewrite the article's date.

Research news extends the original news fields with exactly `publisher`, `author`, `license`, `modified_at`, `first_seen`, `last_seen`, `content_changed_at`, `source_id` and `references`. Source IDs, publishers, rights URLs and HTTPS article hosts/paths are allowlisted. Publication is source-provided; explicit modification may be null. First collection and measured content changes are local clocks. Timestamp-only changes do not count as substantive changes. The original canonical article URL is retained as a reference; article/IOC URLs are never followed for enrichment.

The collector/exporter never calls Ollama. `compose_brief.py --editorial` consumes the already sanitized snapshot and saves a digest-bound cache in ignored `data/editorial/`; rejected drafts stay under its private `review/`. `export_publication.py --publish-prepared` reapplies only a matching checked cache and publishes that same collected snapshot. It performs no recollection or platform/model calls and rejects snapshots older than 24 hours. This avoids regenerating a different reporting window between inference and publication. The original `--publish` command remains a safe immediate-collection/fallback path.

Current version-3 editorial editions bind `headline`, `plan`, `approval_id`, `evidence_digest`, frozen `input`, `input_digest`, `topics`, `window_start`, `window_end`, `generated_at`, `published_at`, `revised_at`, `publication_kind`, `mode`, `version` and `id`. Only weekly publication is active. The builder independently rechecks the repository-owned source-review receipt; unknown prose cannot gain approval by supplying a valid citation ID. Schema 6 retains the same top-level keys as schema 5. Older edition validators remain frozen for archive compatibility. See [weekly generation and review](briefing.md#natural-composition-and-independent-review).

## Official research feeds and reuse policy

Reviewed November 12, 2026. These are public RSS adapters, with no paid API, article scraping, image ingestion or always-running service. At most twenty accepted items per source/fetch are retained into a thirty-day index; accepted article history remains self-contained. Podcast, conference and marketing entries are filtered. First-person/relative source statements retain publisher and publication-date attribution.

| Source | Official RSS | Attribution / rights |
| --- | --- | --- |
| SANS Internet Storm Center | [Handler diaries](https://isc.sans.edu/rssfeed.xml) | SANS Technology Institute, Internet Storm Center; [data-use policy](https://isc.sans.edu/linkback.html), [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). The footer’s Sources & Licenses dialog preserves credit, supplied bylines, original diary links, CC BY-NC-SA 4.0 terms and an adaptation notice. |
| Cisco Talos | [Talos RSS](https://blog.talosintelligence.com/rss/) | Publisher/byline, canonical link and [Cisco terms](https://www.cisco.com/c/en/us/about/legal/terms-conditions.html); no open article license is assumed. |
| Google Threat Intelligence Group | [GTI RSS](https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/) | Publisher/byline, canonical link and [Google terms](https://policies.google.com/terms); no open article license is assumed. |

Only title, attribution, chronology and short complete introductory sentences from the supplied feed description are projected. The eighty-word bound is a maximum, not a target. No full article, `content:encoded`, embedded media or linked body is copied. Long first sentences without a complete bounded formulation remain title-only. Public records retain each publisher's rights URL; source material is not blanket-relicensed by this repository. Reassess terms before changing this scope or commercial reuse. The new research feeds serve public editorial coverage; they are not represented as new MISP/OpenCTI platform imports.

## Publication boundary

The local MISP API, database, raw Markdown, and arbitrary URLs are never collection inputs. Only fixed CISA/CIRCL endpoints and the reviewed official research RSS endpoints below are fetched. CIRCL events must be published with explicit CLEAR/WHITE markings. Conflicting TLP, PAP/IEP constraints, private distribution, and sharing groups exclude event/object/attribute data. Attribute inheritance follows both parents. Missing distribution in the fixed public feed is accepted only with a permissive marking. Unknown TLP values fail closed.

Only CIRCL titles and normalized observations are exported; arbitrary event fields and comments are withheld. Public CIRCL brief excerpts must be the approved short title, at most twenty-five words. CISA retains source descriptions/actions. News consists of short attributed excerpts, without third-party photographs or hotlinks.

Indicators are checked for public hosts/addresses. Common internal suffixes, reserved/private address literals, embedded URL credentials, suspicious key assignments, and contact addresses in text are rejected. Allowlisted public sources and explicit projection are the primary boundary; text heuristics are additional checks, not a universal data-loss prevention claim.

Private sidecars provide candidate selections, typed chronology, fingerprints, and a candidate narrative only. Every original record version and the batch digest must match independently recollected public evidence; selection validation runs again. An inadmissible batch is withheld as a whole. No platform context, private event UUID, model address, or run ID is copied. Prior accepted editions remain. Failed/degraded reports are not promoted. Complete zero-record runs do not create new public archive entries; earlier historical quiet records remain readable.

The backend creates private MISP events even for public intelligence. Those events are not exported. Public CIRCL event URLs identify upstream public evidence and are intentional citations. All source assertions still require analyst review.

## Failures and isolation

Each source can fail independently. Its previous accepted records/news and last-success time remain; health changes to `cached` or `unavailable`. A successful fetch can remove aged-out records. Accepted history retains ninety editions. Cached snapshots are revalidated before use. Synthetic data is rejected by the live exporter, publisher, and deployment build.

The publisher sends JSON over stdin to `gh api`, never reads/prints a token, and constructs a tree containing exactly `snapshot.json`. It refuses unexpected data-branch files. Updates are fast-forward-only: an intervening sibling write fails instead of overwriting it. No working-tree staging or force push is supported.

The orphan `intel-data` branch intentionally has no code or workflow. An explicit dispatch runs `pages.yml` on `main`. It checks out the data separately, validates again, and copies an asset allowlist. Unexpected output files and symlinks stop the build. Only the deploy job has Pages-write/OIDC permissions; runners receive no VM secrets. Daily collection refreshes public data even without a new article. A hosting quota or failure can delay the visible refresh while the last successful static site stays online.

```sh
export PYTHONPATH=src
python3 scripts/export_publication.py
python3 scripts/compose_brief.py --editorial
python3 scripts/export_publication.py --publish-prepared
python3 scripts/build_dashboard.py --snapshot data/publication/snapshot.json
gh run list --workflow pages.yml --limit 5
```

For a fork, enable Actions Pages and update repository configuration/links. The same account running the timer needs authenticated contents-write/workflow-dispatch access. A locked credential keyring can prevent unattended auth; use supported credential configuration without embedding tokens in source or shell arguments.

Collection/data-commit failure returns nonzero to the service journal and retry mechanism. A successful data commit is not deployment success: monitor Actions. If dispatch fails after a commit, rerun `gh workflow run pages.yml --ref main`; the accepted data already exists. Failed deployment preserves the previous site. Static hosting stays available while the VM is offline; fresh collection resumes when the collector returns.

## Calculation and frontend checks

`website/analytics.js` deterministically deduplicates KEV CVE values and IOC type/value pairs. New IOCs use the earliest collection time across all matching observations. Advisories/24h use source publication time and exclude future dates. Charts zero-fill UTC days and count unique catalog additions over seven or thirty days. The supporting report chart counts unique canonical article URLs by source publication date and subject, excluding future dates. Its totals describe the bounded collected index, not all reporting on the internet, distinct campaigns, incidents or attack volume. ATT&CK catalog objects never enter those counts. No chart number or relationship is model-generated. Catalog inclusion is not relabeled as CVSS severity.

The frontend is one page: an asymmetric narrative lead/radar, featured and secondary editorial stories, compact statistics/trends, understated catalog context, and expandable CVEs/archive. The composition chart is available on expansion and is labeled dataset information, not threat activity. The former source/status page and sidebar were removed; operational details remain here. Global search includes STIX names/IDs. Dialogs show original evidence and resolved catalog relationships. Source strings are HTML-escaped; links require approved HTTPS hosts. The Content Security Policy restricts scripts, images, fonts, and connections to the static origin. Charts include accessible labels and data tables.

Reader-facing destinations are selected from validated CISA/SANS/Talos/Google article URLs or internal CVE/indicator detail views; URLs are not invented from CVE names or dates. Technical views retain the original source URLs with explicit “Raw source data” labels for JSON/CSV/XML. Homepage evidence groups deduplicate shared records across editorial topics, while the archive retains full reports. Additional stories suppress exact featured article IDs/URLs before grouping; CVE overlap only affects related-story ordering and never alone deletes a report. Research categories are derived deterministically from source title/description terms; they describe report subjects, not verified attack classifications.

Run Python tests, Node calculation tests, the infrastructure validator, synthetic private reporting, and empty/demo builds. Browser acceptance uses real public data and prior validated briefs at widths 390, 768, and 1440: four primary views, no horizontal overflow or browser/CSP errors, metric agreement, chart controls, report selection, CVE filtering, search, and dialog Escape handling. Screenshots contain only public data. Browser tooling is a development aid, not a runtime dependency.


## Reader attribution and chart access

The footer contains GitHub and Sources & Licenses. The keyboard-accessible dialog retains full MITRE license text and copyright, SANS credit/license and modification notice, available source bylines and original links, other publisher rights and the Newsreader license. The ATT&CK context also carries MITRE’s reproduction notice and a link to the bundled license. Original source links remain beside stories and in technical evidence; attribution has not been replaced by a generic homepage link.

Placement was reviewed against [MITRE’s terms](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), the [SANS data-use policy](https://isc.sans.edu/linkback.html) and [CC BY-NC-SA 4.0 §3](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.en#s3), including its allowance for a reasonable linked attribution resource. Cisco/Google rights links and supplied attribution remain; their content is not assigned an open license. This changes presentation, not collection scope or downstream reuse rights.

The visible Chart data disclosure/table is removed. The same `dailyKev` calculation drives 7D/30D bars, accessible per-date labels and a nonvisual UTC-series description. `snapshot.json` retains original catalog dates and all observations; `chartRows` and report-count helpers remain available for technical analysis. No data is deleted or inferred attack-frequency chart introduced.
