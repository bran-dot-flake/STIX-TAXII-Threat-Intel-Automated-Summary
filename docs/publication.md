# Public publication contract and operations

`scripts/export_publication.py` independently recollects original public sources and optionally publishes through existing `gh` authentication. It does not call platform APIs or Ollama. The staged scheduler invokes it when `TI_PUBLICATION_ENABLED=true`, including after backend failures. All existing private reporting paths remain available.

## Schema version 1

`src/ti_brief/publication.py:validate_snapshot` is the executable contract. Unknown object keys are rejected. The live validator rejects synthetic data; only explicit `build_dashboard.py --demo` permits the labeled fixture.

| Object | Exact fields |
| --- | --- |
| Snapshot | `schema_version` (1), `synthetic`, `collected_at`, `exported_at`, `sources`, `records`, `news`, `reports` |
| Source health | `id`, `status` (`ok`, `cached`, `unavailable`), `attempted_at`, `last_success_at` |
| Observation | `id`, `source`, `source_url`, `kind`, `value`, `title`, `description`, `action`, `published_at`, `first_seen`, `last_seen` |
| News | `id`, `source`, `source_url`, `title`, `excerpt`, `published_at`, `category`, `artwork` |
| Brief | `id`, `generated_at`, `mode` (`ollama-extractive`, `deterministic`, `quiet-day`), `evidence_count`, `items` |
| Brief item | `id`, `excerpt`, `title`, `source`, `source_url`, `value`, `kind`, `action`, `published_at` |

Limits: 5,000 observations, eighteen news items, ninety accepted editions, eight source observations per brief, 240 characters per validated brief excerpt, and twenty-two words per news excerpt. Evidence IDs are 24-character hashes. Indicator values are canonicalized and defanged. Source IDs are `cisa-kev`, `circl-osint`, and `cisa-advisories`. Artwork is one of two bundled original SVGs.

Timestamps are ISO 8601 UTC; source date-only values display as midnight UTC. `published_at` can be null when unknown. `first_seen` means first collection by this publication, not source discovery or incident occurrence. Initial IOC counts form a bootstrap baseline. Catalog dates specifically mean KEV `dateAdded`.

`collected_at` is the latest successful adapter fetch, not proof all adapters succeeded. Each source retains its own success time. `exported_at` is sanitized snapshot creation; briefs carry their own generation time. The builder creates a separate `build.json`. Build time is explicitly distinguished from deployment completion, which is recorded in the linked public Actions log.

## Publication boundary

The local MISP API, database, raw Markdown, and arbitrary URLs are never collection inputs. Only the original fixed CISA/CIRCL sources are fetched. CIRCL events must be published with explicit CLEAR/WHITE markings. Conflicting TLP, PAP/IEP constraints, private distribution, and sharing groups exclude event/object/attribute data. Attribute inheritance follows both parents. Missing distribution in the fixed public feed is accepted only with a permissive marking. Unknown TLP values fail closed.

Only CIRCL titles and normalized observations are exported; arbitrary event fields and comments are withheld. Public CIRCL brief excerpts must be the approved short title, at most twenty-five words. CISA retains source descriptions/actions. News consists of short attributed excerpts, without third-party photographs or hotlinks.

Indicators are checked for public hosts/addresses. Common internal suffixes, reserved/private address literals, embedded URL credentials, suspicious key assignments, and contact addresses in text are rejected. Allowlisted public sources and explicit projection are the primary boundary; text heuristics are additional checks, not a universal data-loss prevention claim.

Private sidecars provide candidate selections and fingerprints only. Every original record version and the batch digest must match independently recollected public evidence; selection validation runs again. An inadmissible batch is withheld as a whole. No platform context, private event UUID, model address, or run ID is copied. Prior accepted editions remain. Failed/degraded reports are not promoted. Complete zero-record runs become explicit quiet-day editions, without claiming no threats exist.

The backend creates private MISP events even for public intelligence. Those events are not exported. Public CIRCL event URLs identify upstream public evidence and are intentional citations. All source assertions still require analyst review.

## Failures and isolation

Each source can fail independently. Its previous accepted records/news and last-success time remain; health changes to `cached` or `unavailable`. A successful fetch can remove aged-out records. Accepted history retains ninety editions. Cached snapshots are revalidated before use. Synthetic data is rejected by the live exporter, publisher, and deployment build.

The publisher sends JSON over stdin to `gh api`, never reads/prints a token, and constructs a tree containing exactly `snapshot.json`. It refuses unexpected data-branch files. Updates are fast-forward-only: an intervening sibling write fails instead of overwriting it. No working-tree staging or force push is supported.

The orphan `intel-data` branch intentionally has no code or workflow. An explicit dispatch runs `pages.yml` on `main`. It checks out the data separately, validates again, and copies an asset allowlist. Unexpected output files and symlinks stop the build. Only the deploy job has Pages-write/OIDC permissions; runners receive no VM secrets.

```sh
export PYTHONPATH=src
python3 scripts/export_publication.py
python3 scripts/export_publication.py --publish
python3 scripts/build_dashboard.py --snapshot data/publication/snapshot.json
gh run list --workflow pages.yml --limit 5
```

For a fork, enable Actions Pages and update repository configuration/links. The same account running the timer needs authenticated contents-write/workflow-dispatch access. A locked credential keyring can prevent unattended auth; use supported credential configuration without embedding tokens in source or shell arguments.

Export/publish failure returns nonzero to the service journal and retry mechanism. A successful data commit is not deployment success: monitor Actions. If dispatch fails after a commit, rerun `gh workflow run pages.yml --ref main`; the accepted data already exists. Failed deployment preserves the previous site. Static hosting stays available while the VM is offline; fresh collection resumes when the collector returns.

## Calculation and frontend checks

`website/analytics.js` deterministically deduplicates KEV CVE values and IOC type/value pairs. New IOCs use the earliest collection time across all matching observations. Advisories/24h use source publication time and exclude future dates. Charts zero-fill UTC days and count unique catalog additions over seven or thirty days. No chart number or relationship is model-generated. Catalog inclusion is not relabeled as CVSS severity.

The four views cover overview, dated brief history, the searchable/paginated KEV register, and source health. Global search and evidence dialogs provide details. Source strings are HTML-escaped; links require approved HTTPS hosts. The Content Security Policy restricts scripts, images, fonts, and connections to the static origin. Original illustrations are bundled SVG files. Charts include accessible labels and data tables.

Run Python tests, Node calculation tests, the infrastructure validator, synthetic private reporting, and empty/demo builds. Browser acceptance uses real public data and prior validated briefs at widths 390, 768, and 1440: four primary views, no horizontal overflow or browser/CSP errors, metric agreement, chart/category filters, report selection, CVE filtering, search, and dialog Escape handling. Screenshots contain only public data. Browser tooling is a development aid, not a runtime dependency.
