# Validation record

This record separates application acceptance from container startup and records failures as well as passing checks. Existing prompt-injection repositories and their uncommitted artifacts were preserved. The agent did not reboot the VM or modify its networking, swap, or Ollama service configuration.

## Current validation summary

Last reviewed: **2026-11-12**. Historical figures below are acceptance samples, not current collection totals.

| Area | Verified evidence |
| --- | --- |
| MISP / OpenCTI | 41 source observations passed exact value/pattern and MISP-provenance read-back; private events and durable checkpoints retained. |
| STIX / TAXII | 220 original objects in a bounded live pilot; source versions/relationships, resumable pages and incremental replay tested. A three-object OpenCTI bridge replay made zero additional writes. |
| Reporting | A 321-word checked weekly edition was built from live source evidence. Two real CPU Ollama drafts failed the prose gate and retained fallback; the earlier 143-word model overview and private reporting run remain recorded below. |
| Publication | HTTPS Pages deployment and original-source validation verified; the public dataset remains separate from private platform databases. |
| Regression checks | 109 Python tests (including optional STIX dependencies), 32 Node tests, repository-link/SVG checks and Chrome at 390/768/1440 passed locally; the [CI workflow](../.github/workflows/ci.yml) runs the same suites on supported Python versions. |
| Resources / automation | Approximately 10 GiB guest RAM; two-thread CPU inference. The approved daily 08:00 UTC timer remains active. |

**Limits:** bounded feed/catalog coverage; no inferred actor/technique relationships; no general verifier of unrestricted LLM prose. The November 12 daily service completed successfully before the hybrid upgrade. The new hybrid stages are tested separately; their complete updated scheduled sequence awaits its next daily activation. A backup restore and production-scale operation have not been demonstrated.

Private run records, reports and journals remain in the lab, outside Git. The dated sections below retain failures, resource observations, acceptance commands and public Actions references. [Resource history](resources.md) · [Current operations](deployment.md).

## Reproduce automated checks

From the repository root, using Python 3.11+ and Node 24:

```sh
python3 -m venv work/check-venv
work/check-venv/bin/python -m pip install -r requirements-stix.lock
PYTHONPATH=src work/check-venv/bin/python -m unittest discover -s tests -v
node --test tests/dashboard.test.mjs
python3 scripts/check_repository.py
python3 scripts/validate.py
python3 scripts/build_dashboard.py --demo
```

The optional dependencies enable the STIX/TAXII tests; without them, those cases are explicitly skipped. In PowerShell, set `$env:PYTHONPATH='src'` and use the virtual environment's Windows Python path. Browser acceptance uses the existing [Chrome/Playwright runner](../scripts/check_dashboard.cjs); the [CI workflow](../.github/workflows/ci.yml) shows its pinned development setup. It does not add a browser or service to the deployed website.

## Historical acceptance record

## Assessment and recovery

On 2026-11-10, read-only checks found an Ubuntu 26.04 guest with 9,481 MiB RAM, three CPU threads, no swap, 34 GiB free disk, native Ollama 0.40.16 and an existing 2 GB llama3.2 model. Docker was absent. The first model test coincided with a user-confirmed VM crash; its cause remains unconfirmed, with no retrieved OOM/panic evidence.

The user expanded guest RAM/disk and closed other VMs. Recovery checks observed 10,260 MiB RAM, about 9,067 MiB available and 135 GiB free disk. After explicit approval, Docker 29.1.3 and Compose 2.40.3 were installed and the Docker group granted to vboxuser. No unrelated packages were upgraded or removed in the reviewed installation plan.

## Live acceptance on 2026-11-10

| Check | Observed result |
| --- | --- |
| MISP API | Authenticated version 2.5.51 returned |
| Idempotent MISP write | A private synthetic event was created, updated with the same UUID and read back with the expected attribute |
| Live ingestion | 41 observations from CISA KEV and a bounded CIRCL OSINT sample persisted in SQLite and MISP |
| OpenCTI API | Authenticated health and the production context query succeeded on 7.261109.0 |
| Exact synchronization | All 41 observations passed exact entity/pattern plus MISP event reference checks |
| Verified entity mix | 21 CVEs, 5 MD5, 5 SHA1, 5 SHA256, 3 URLs, 1 domain and 1 IP |
| Native relationships | The connector created indicator/observable based-on relationships and source-referenced reports; no actor/technique links were guessed |
| Local model | Existing llama3.2:latest, digest prefix a80c4f17acd5, 3.2B Q4_K_M, CPU-only |
| Validated real brief | Two-record brief completed in 21.78 seconds with platform containers stopped |
| Full staged job | Eight-record preparation: 6.88 seconds; inference/reporting: 45.83 seconds; both UIs restored; orchestrator exit 0 |
| Model unloading | Ollama /api/ps returned an empty model list after completion |
| Persistence | Named volumes retained across stops/restarts; records remained queryable and checkpoints preserved |
| Secret isolation | Actual reports, state, logs and .env remain private and ignored by Git |

Private report evidence: reports/live/2026-11-10T212333.929775Z-run-8.md and reports/live/2026-11-10T212745.077425Z-run-10.md. Ten observations were acknowledged across those completed runs; 31 remained queued afterward. Bounded reports do not imply that unselected records were assessed.

## Failures found and corrected

- MISP modules exceeded a 256 MiB cap and generated Docker OOM events. A 512 MiB cap produced a stable approximately 399 MiB process.
- The nginx image includes curl rather than wget. Its probe now checks the login page with the installed tool.
- The deployed MISP connector omitted standalone vulnerability attributes. A CVE-only native GraphQL bridge now follows MISP read-back and attaches MISP and original-source references. The connector remains the IOC writer.
- Broad search candidates were insufficient for identity verification. Context now uses exact type/name filters plus independent pattern/value and MISP-reference checks.
- The connector's native MD5 pattern omits algorithm-name quotes. The equivalent valid STIX form is accepted and covered by a regression test.
- One IP was missed by small timestamp-based batches. The search batch was increased to 100, above the default 50-write bound, and the existing event reconciled without changing its UUID. Strict preparation can requeue an unverified IOC once.
- The initial post-recovery model output paraphrased evidence and was rejected. It produced a marked fallback without acknowledging records. Schema alternatives now bind each ID to exact source choices; real inference subsequently passed. No execution tools are supplied to the model.
- The existing user service manager retained its old Docker group list. The reviewed system unit executes as vboxuser with the approved Docker group, avoiding a desktop-session restart or user lingering.
- Feodo returned a March 2026 freshness timestamp during November assessment. It remains disabled by default and is rejected by the freshness gate. Its CSV URL/schema were corrected.

## Resource observations

The configured combined container cap is 6,464 MiB, excluding the OS and native Ollama. Preflight reserves another 1,024 MiB of available guest memory. Representative combined measurements: about 1.2 GiB search, 0.4-0.6 GiB OpenCTI, 399 MiB MISP modules, 0.2 GiB MISP core, with smaller database/worker/broker/cache processes. Approximately 6 GiB guest memory remained available with both platforms resident.

The two-record inference measured 8,878 MiB available before and 6,567 MiB at completion; the eight-record run measured 8,527 MiB before and 6,744 MiB at completion. These are samples, not exact peaks. Platforms were stopped during inference, the model unloaded afterward, and no swap was configured or used.

On 2026-11-11, a read-only check showed all 12 containers still up after approximately 16 hours, with dependency/application health checks passing and 6,171 MiB guest memory available. This supports overnight idle stability for this small dataset, not production-scale throughput or upstream-supported sizing.

## Automated checks and remaining acceptance

At backend acceptance, the 28-test suite passed locally. It covers normalization, stale feeds, bounded CIRCL parsing, deduplication, priority/backlog handling, nondestructive migration, MISP HTTP contracts, CVE upserts, exact OpenCTI provenance, model validation, secrets, snapshot expiry, locks and failed-run checkpoints. CI checks Python 3.11/3.13/3.14, Compose consistency, image locks, Compose syntax and the offline demo. An earlier 23-test commit passed [all jobs](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/42893100816). Consult current-commit checks for the expanded suite.

## Daily system service accepted on 2026-11-11

The owner explicitly approved and installed the reviewed system service/timer. The service executes as `vboxuser` with the approved Docker group. A real systemd-managed run completed with `Result=success`, `ExecMainStatus=0` and no retries, restored both platform UIs, and unloaded Ollama. It took 6 minutes 20.858 seconds overall and recorded a 48.3 MiB orchestration-process memory peak. Its eight-record inference/reporting phase took 103.78 seconds and wrote `reports/live/2026-11-11T132554.705191Z-run-12.md`. Twenty-three observations remained queued afterward; all 41 historical observations were retained even though two aged out of the feed's current collection window.

The timer is enabled for daily 08:00 UTC with up to five minutes of jitter, independent of interactive logins. The next observed activation was 2026-11-12 at 08:04:05 UTC (03:04:05 US Eastern). Missed executions are persistent; failures retry after 15 minutes, bounded to three starts in six hours.

At backend acceptance, TAXII and broader threat-entity feeds were still future work; the STIX/TAXII acceptance below closes the ingestion gap. Backup restoration and larger-scale operation remain extensions. This is a functional small-data lab below OpenCTI's published production memory recommendations.

## Public observatory accepted on 2026-11-11

[PR #2](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/pull/2) adds EMBER over the working backend. The source branch and merged main passed the expanded CI matrix: 39 Python tests on Python 3.11/3.13/3.14, four Node calculation tests, the infrastructure validator, Compose configuration, isolated synthetic reporting, and empty/synthetic static builds. [Main CI evidence](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/43042036332).

The independently collected live snapshot contains 159 public observations (114 KEV entries and 45 unique IOCs), eighteen CISA advisories, and two validated local brief editions. Each source fetched successfully. Exact selection/version validation preserved the existing LLM output without another inference call. A comparison against the VM's actual secret values reported zero matches; no private platform context was present in the export.

The publisher created the isolated `intel-data` branch with exactly one sanitized `snapshot.json`. A subsequent real CLI publication succeeded with DBus and SSH-agent environment removed and Linux no-new-privileges enabled, demonstrating that this flow does not depend on an interactive desktop or SSH agent. It dispatched the workflow and reached a successful Pages deployment. [Publication deployment evidence](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/43042142517).

GitHub Pages inherits the owner's existing domain. Both the standard Pages project URL and [the HTTPS custom-domain project URL](https://brandonchaney.dev/STIX-TAXII-Threat-Intel-Automated-Summary/) returned the EMBER website successfully; the standard URL redirects to the existing domain. HTTPS enforcement is enabled for this repository. The domain itself was not changed.

Headless Chrome exercised all four primary views at widths 390, 768, and 1440, including the deployed project URL. Checks covered exact metric agreement with JSON, 7/30-day charts, category filters, report selection, CVE search, global search, dialog Escape, and no horizontal overflow or browser/CSP errors. Separate local checks covered empty, synthetic, stale/cached, and unavailable-data states. Screenshots in `docs/images` contain only public data. Original SVG editorial illustrations need no third-party image service.

The collector checkout was fast-forwarded to the merged source, and `TI_PUBLICATION_ENABLED=true` was added to its private environment without changing platform/model settings. No new administrative service or model was installed. The previously approved timer remains active; the observed next activation is November 12 at 08:04:05 UTC. It will run the public hook after its existing staged reporting workflow. Full automatic daily execution after this change awaits that scheduled activation; the publisher itself has been verified directly under the service's relevant authentication/privilege constraints.

The static site stays accessible while the VM is offline, with collection age shown explicitly. It cannot collect new data during that outage. Only complete publicly eligible report batches appear in public history; private or restricted evidence remains local. See the [publication contract](publication.md) for schema, coverage, failure behavior, and operating commands.

## Compact frontend and STIX/TAXII acceptance — 2026-11-11

[Earlier news-index screenshot](images/intelligence-desk.png) is retained as a historical UI reference; current screenshots are linked from the README.

The revised frontend consolidates the prior views into a single page. The sidebar, decorative masthead, standalone status section, and repeated story art were removed. A multi-finding brief appears first, followed by four metrics, compact trends, grouped stories, and expandable CVEs/archive. Optional ATT&CK context remains collapsed until requested. Search includes catalog names/IDs and detail dialogs retain original relationship IDs/direction.

Live verification used MITRE's original TAXII 2.1 discovery endpoint, default API root, and Enterprise collection. Bounded requests parsed and stored 220 original STIX objects. Repeated calls resumed later pages, preserved existing versions, and exercised the completed definitions stream's incremental date-added query. The public gate accepted 61 named catalog objects and five resolved relationships; incomplete, inactive, unsupported, and unmarked/restricted context remained local. This is sampled coverage, not a full ATT&CK download or incident activity measure.

An OpenCTI pilot upserted/read back four catalog entities/relationships through native APIs. A separate real three-object source sample (two endpoints plus their relationship) completed read-back and repeated with zero additional writes. Original STIX IDs, native endpoint IDs, relationship type/direction, and source names were checked. No new MISP writer, container, model, or administrative unit was introduced.

The expanded suite contains 56 Python tests with the optional STIX dependencies installed and six Node calculation/selection tests. It covers representative SDOs/SCOs/reports, raw references, version conflicts, revocation/deprecation, observable variants, marking definitions, pagination/resume/incrementals, expired tokens, configuration replay, rate deferral, credential isolation, platform checkpoint/read-back, cached publication during interrupted imports, optional-stage failures, and side-effect-free scheduler help. Existing ingestion/report tests remain intact. Development browser checks at 390/768/1440 passed with no page/CSP errors or overflow; they exercise search, chart filters, vulnerability details, archive selection, and live catalog relationships. CI adds the reproducible browser runner against the labeled fixture.

Public snapshots now write schema 2 with a strictly validated STIX projection while retaining schema 1 read compatibility. The static Pages build still needs no STIX runtime dependencies or lab access. The revised source enables the existing daily hook to run bounded collection and the optional catalog bridge. [STIX operations](stix-taxii.md) documents authentication, limits, cached failure behavior, licensing, and the narrow bridge's lifecycle limitations.


## Grouped narrative and retro refinement — 2026-11-11

The latest accepted edition (`dfd03e14929f19118635f987`, original generation 13:46:58 UTC) contains eight observations: three distinct KEV vulnerabilities and five CIRCL indicators from one MoustachedBouncer event. The revised page presents four topics and retains every technical observation under its original source. The original generation time and prior edition remain intact. This edition's source dates predate its reporting window, so it explicitly presents historical context rather than new attacks.

A real call to the existing CPU-only Ollama model produced an accepted fact-cited overview and four topic summaries/significance statements. The bounded call took approximately nine minutes with two inference threads. Observed model-process RSS was approximately 2.42 GiB, with about 3.64 GiB guest memory still available during inference; these are samples, not measured peaks. The model was requested to unload afterward. No platform service, model, package, or administrative unit was added. Redundant ledger fields were subsequently removed from the prompt without changing the independent claim validator or public contract.

A separate original-source export succeeded for all three adapters, retained 159 public records, eighteen advisories, and two editions, and projected 160 catalog objects/twelve resolved relationships from the existing STIX store. The already generated model composition was checked in full against this independent projection before rebinding its input digest to the now available source-modification metadata. Ordinary exporter/cache handling never silently rebinds a digest: a mismatch rejects that candidate and uses the deterministic fallback.

Local validation passed 67 Python tests with optional STIX dependencies, seven Node calculation/selection tests, the locked infrastructure validator, and headless Chrome acceptance at 390/768/1440 widths. New cases cover eight-to-four provenance grouping, unrelated CVEs/events, duplicate/conflicting observations, instruction-like source content, unsupported prose despite valid IDs, invented CVEs/statistics/mitigations, wrong references/freshness, chronology, metadata-only republication, unavailable Ollama, quiet days, and the public boundary. Existing ingestion, STIX/TAXII, synchronization, expiry, and checkpoint tests remain passing. Browser checks also verify section order, all four topic headings, complete-excerpt expansion, metric agreement, filters, search, archives, and STIX relationship dialogs with no page/CSP errors or horizontal overflow.

The screenshots use the independently exported public data and accepted model composition. Schema 3 preserves strict field allowlists and schemas 1/2 input compatibility. The daily staged path adds the narrative call after exact-excerpt validation; a failed narrative call publishes only the checked fallback. The existing timer will exercise that updated staged path at its next scheduled activation; the live narrative call and independent exporter were verified directly during this change.


## Publication-wide editorial acceptance — 2026-11-11

The prior front-page brief described an older eight-record batch while the independently collected news already reported six November 10 KEV additions. The new editorial edition uses the complete validated publication instead of that queue. A live original-source export at 18:08:21 UTC retained 159 public records, eighteen advisories, both original batch reports, and 160 STIX catalog objects/twelve source relationships. Its curated current input includes all six November 10 CVEs plus the corresponding CISA bulletin. The four editorial topics cover the catalog additions, an explicitly source-reported Barracuda CVE chain, Chromium sandbox code-execution exposure, and BroadWorks configuration-read exposure. The historical MoustachedBouncer batch is retained in the archive and is not recycled as current news.

The existing CPU model produced source-cited sentence claims and supporting summaries. All overview claims passed the independent source-formulation check. Supporting summaries that repeated headlines were withheld, retained in a private review artifact, and replaced from the checked source ledger. The checked sentences were arranged into developments and significance/guidance, producing a 143-word two-paragraph overview. The entire final plan, conditions, original public input, topic references and digest passed validation again. This does not demonstrate reliable verification of unrestricted paraphrases; unsupported overview prose still requires the deterministic fallback or private review.

The revised page uses an asymmetric lead/radar, one featured article, secondary reports and a smaller headline index. Source dates and links remain visible. The composition chart is collapsed under the compact trend chart and catalog context is separate and understated. The black/charcoal/cream/orange palette is unchanged. Browser acceptance passed at 390, 768 and 1440 widths for both live public data and the schema-4 synthetic demo, with no page/CSP errors or overflow. The same public-data sample measured 1,650 pixels high at desktop width versus 1,628 previously, and 2,876 pixels at phone width versus 3,120 previously: a longer substantive lead fits in approximately the same desktop space and about 8% less mobile scrolling. Screenshots were inspected visually.

Local validation passed 85 Python tests with optional STIX dependencies and eight Node tests, plus infrastructure validation and empty/demo/live static builds. New cases exercise current advisories without a private batch, same-date catalog stories without merging CVE entities, explicit-chain requirements, historical collection/quiet windows, proven updates versus modification clocks alone, exact-event grouping/conflicts/injection, explicit historical/STIX references, unsupported claims despite valid IDs, Unicode/negation/number attacks on claim matching, partial summary withholding, input-bound caches/history, strict public projections, bounded fallback size and four-source topic coverage, and prepared publication without recollection. Existing backend/STIX/TAXII, checkpoint, synchronization, and failure tests remain intact.

Staged publication now collects once, composes from that fixed sanitized snapshot, and publishes the prepared result. It replaces the redundant private-batch narrative call, retaining exact-excerpt inference and all original reports. At the pre-run check the VM had about 6,197 MiB available memory and 125 GiB free disk. The editorial command checks at least 3,500 MiB available memory and requests model unload. No administrative unit, package, model or service change is required. The full updated systemd sequence awaits its next scheduled activation; source collection, real model output, independent finalization and publication components are tested directly.


## Reader evidence and usability refinement — 2026-11-11

The front-page Supporting evidence section contains independently expandable groups and records, with no copied overview or radar summaries. For the current November 10 briefing, six unique CVEs and one CISA announcement appear once, despite their shared editorial topics. The archive retains full reports. Reader links use the original approved human article or an internal detail view; JSON feeds remain unchanged and explicitly labeled Raw source data in technical views. All eighteen CISA article URLs returned HTTP 200 HTML from the VM; the lead URL returned the expected “CISA Adds Six Known Exploited Vulnerabilities to Catalog” page title at its original URL.

The visible category filters and placeholder excerpt labels are removed. Latest Intelligence filters exact featured IDs/URLs before grouping, keeps distinct related CVE reports and older bulletins, and preserves the complete underlying dataset/search/archive. Tests verify these distinctions, unsafe link rejection, evidence counts/deduplication, context/update metadata, empty excerpts, unchanged overview text, independent disclosures, raw-link labels, and reader detail dialogs. All 85 Python tests and eighteen Node tests pass. Chrome checks at 390/768/1440 pass against real and synthetic data, with additional isolated legacy/quiet/placeholder presentation cases and no page/CSP errors or overflow. The built real publication JSON equals the original payload; backend schemas, model output, platform integrations and checkpoints are unchanged.


## Final publication and repository polish — 2026-11-11

Global search now groups CIRCL observations by exact original event URL, deduplicates CVEs/source articles across current and archived datasets, and retains exact hash/domain/IP/URL/ATT&CK lookup. Displayed indicators remain defanged. Matching archived observations open their actual evidence version. Result labels distinguish reports, vulnerabilities, advisories and ATT&CK entity types without adding search filters.

All 160 current public ATT&CK entries had valid names/types/identifiers; 139 lacked resolved relationships in the bounded sample. Their detail dialogs now omit empty relationship sections. Defensive card checks exclude malformed identities without inventing titles; existing source links, tactics and resolved edges remain. The public schema contains no object descriptions, so no new enrichment/export fields were introduced. The KEV bar series and totals are unchanged; chart tables default to nonzero dates and expose the complete series through Show all days.

The existing compact header received serif masthead typography and thin rules; no font download, CDN or new visual panel was added. The README was reduced from 20,396 to approximately 8,700 bytes, preserving its centered title/rule/technology/badges/description/navigation/rule order. The dynamic CI badge references the actual workflow. A 1,280 × 290 SVG diagram separates independent original-source recollection from eligible private-lab context. The detailed Mermaid path is retained in deployment documentation. The diagram was rendered and inspected; current desktop/mobile screenshots were refreshed.

Local checks passed 85 Python and 26 Node tests, the infrastructure validator, real/demo builds, and Chrome acceptance at 390/768/1440, including grouped and exact-identifier search, sparse catalog dialogs, all-days chart tables and the existing controls. Repository checks cover nine Markdown documents, local anchors/paths, four SVGs and exclusion of private/runtime paths. An additional tracked-file audit found no high-confidence private-key/token patterns or duplicate PNGs. The earlier news-index crop remains linked as historical evidence; legacy illustration assets remain referenced by the build/metadata contract. Existing operational/security material was retained in its focused documents, with stale batch-versus-editorial wording corrected. No runtime backend, schema, synchronization or model change was made.


## Historical hybrid reporting acceptance — 2026-11-12

Daily collection now prepares data independently of weekly/interim editorial selection. Local regression checks cover quiet-day retention and immutable publication dates, adjacent seven-day UTC boundaries, repeat-run identity, significant and routine developments, same-CVE article grouping, newly collected history, measured content changes versus timestamp edits, source outages, model rejection/unavailability, retry-cache reuse and failed-upload checkpoints. Synthetic tests use clearly fictional source records; they are not published as live intelligence.

The three official research RSS adapters were tested against live SANS ISC, Cisco Talos and Google Threat Intelligence endpoints. An isolated source-only checkout under ignored `work/hybrid-acceptance/` on the VM successfully collected all six configured sources, with 148 public observations and 39 retained source reports in the November 12 acceptance snapshot. Those are bounded samples at that time, not permanent dashboard totals or complete publisher archives. No new platform integration is claimed for research RSS.

A first real weekly draft from the existing CPU llama3.2 model was rejected for omitted lead facts and unsupported supporting wording; its checked fallback was retained. The rejected draft remains private under the acceptance cache. A narrowed output schema restricts overview and per-topic fact choices without relaxing the independent claim gate. Model retries are validation work, not automatic unbounded generation. A second real attempt with the narrower schema also required the checked fallback; the final schema additionally restricts each overview claim to one fact ID. No model wording was promoted by weakening validation. Model unloading was observed after the first attempt; about 3.7 GiB remained available during inference, returning above 6 GiB afterward. No host/VM memory, firewall, model, package or system-timer settings changed.

Browser checks include original controls, grouped/exact search, sparse ATT&CK dialogs, source-chart totals, a retained briefing on a quiet day, weekly plus interim presentation, empty first publication and 390/768/1440 px layouts. Both real-data and synthetic builds passed without browser errors or horizontal overflow. Source-report counts use canonical URLs and source dates; no actor/malware attack-volume statistics are inferred.

Private acceptance inputs, candidate caches and rejected drafts are under `work/hybrid-acceptance/` on the VM. They are not repository contents or Pages artifacts. The last full scheduled run before this change returned `Result=success`, `ExecMainStatus=0`; this does not claim a completed scheduled hybrid run.

The final local suite passed 109 Python tests (no skips with the optional STIX dependencies), 32 Node tests, infrastructure validation and repository checks. Empty, synthetic and live-data builds passed Chrome at all three widths. The updated publication-date test covers a prepared snapshot crossing UTC midnight before upload. Current source-only deployment does not claim another complete systemd-managed hybrid cycle.


Release verification: [PR #9](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/pull/9) merged at `f5d666e`. Its [CI run](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/43240609658) passed Python 3.11/3.13/3.14 and Chrome; [Pages build/deploy](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/43240630346) passed. Live HTTPS acceptance at 390/768/1440 found no browser errors or overflow. Public data commit `1309179` contains a 321-word weekly fallback, six healthy sources, evidence cutoff `2026-11-12T14:13:20+00:00` and independent publication time `2026-11-12T14:46:06+00:00`. Ollama reported no loaded models afterward. Only `main` and `intel-data` remain.

The release CI included 107 tests. Two additional chronology regressions now cover a prior report's substantive update entering the next weekly retrospective and exclusion of content modified after a closed weekly cutoff. Their fixes preserve the current public payload and rendered assets; the follow-up local suite contains 109 tests. Research chronology is also bounded by its edition cutoff. Hosted CI can be dispatched explicitly through the workflow without duplicate push/PR runs; the next scheduled full hybrid cycle is still pending.


## Weekly executive refinement — 2026-11-12

The active path now uses completed weekly windows only. Local validation passes 128 Python tests (including optional STIX/TAXII), 33 Node tests, infrastructure/repository checks, and empty/demo/live static builds. Regression covers daily refresh without interim editions, window identity and overlap, quiet/source/model failure retention, pending-proposal reuse, source-version-bound review, free-text generation, unsupported numbers/identifiers/claims, source copying, date distinctions, real SANS/Talos November Patch Tuesday grouping with conflicting totals, explicit revision identity and failed-upload checkpoints. Legacy validators remain tested for historical archives.

The inspected previous model calls completed and failed the claim interface/wording gate. Two new free-text trials were held privately for quality and factual defects; neither is claimed as autonomous acceptance. The corrected public overview is 225 words across three paragraphs, labeled `ollama-edited-reviewed`. Its receipt records Codex-assisted editorial review, exact plan and evidence digests, and per-claim source assessments. Novel prose still requires explicit review; IDs alone do not prove support. The current revision preserves the weekly ID and original publication date.

Chrome acceptance passes against real and labeled synthetic data at 390/768/1440 pixels without page/CSP errors or horizontal overflow. The opening has one concise weekly period, compact one-sentence radar items and a locally hosted licensed Newsreader headline. The original masthead, navigation, palette, evidence/search/register/ATT&CK/archive controls and KEV calculations remain. Source-report calculations remain available, but their chart is removed. Current desktop/mobile screenshots were visually inspected. Hosted validation and deployment are verified through the linked GitHub checks and Pages run for the corresponding commit, rather than inferred from local builds.


Release verification: [PR #10](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/pull/10) merged at `e13c86b`. [Hosted CI](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/43260293062) passed Python 3.11/3.13/3.14 and Chrome; [Pages build and deployment](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/43260575133) passed. Live HTTPS acceptance at 390/768/1440 passed with no browser errors or overflow, and the published JSON plus six frontend/font/license assets matched the reviewed repository bytes. GitHub-rendered README images and anchors passed on main.

Data commit `d9f41fe` revises the same weekly ID `8336a53a052b1eb30ee0093b`, retaining original publication `2026-11-12T14:46:06+00:00`, source cutoff `2026-11-12T14:13:20+00:00` and window November 2 08:00–November 9 08:00 UTC. Its separate revision time is `2026-11-12T16:36:43+00:00`. Current records, news, STIX context, batch reports and edition count are unchanged. The VM's normal composition rerun returned `weekly-not-due`; its existing daily timer remains active with next activation November 13 at approximately 08:01 UTC. Ollama reported no loaded models afterward. No package, model, system unit or other administrative setting was changed. This verifies the components and live deployment, not a new full systemd-managed private-platform cycle. Only `main` and `intel-data` remain.



## Concise executive summary and layout refinement — 2026-11-12

The same accepted November 2–9 evidence now supports a 114-word, two-paragraph lead, compared with the previous 225 words and three paragraphs. [Full before/after text and measured geometry](editorial-comparison.md) preserve the comparison. The final headline identifies LLMJacking’s billing consequence. XCPE’s affiliate business receives secondary coverage; scoped SSH observations stay in radar. All ten sentence/radar claims have explicit source-bound review; qualified manufacturer attribution remains qualified.

The writer now produces plain paragraphs before citation annotation, instead of mixing prose and evidence-ID enums. Raw drafts are deliberately incompatible with public plans and always remain private until sentence-level source assignment, mechanical checks and explicit review. Two structured trials and one plain-prose trial completed normally. The final trial produced 168 words but still contained unsupported assessment/law-enforcement claims and filler, so the published candidate was edited and reviewed. This is not autonomous model acceptance. Existing registry receipts and historical three-paragraph editions remain valid; no source, schedule, integration, privileged setting, service, model or dependency was added.

Local checks pass 131 Python tests including optional STIX/TAXII, 33 Node tests, infrastructure/repository checks and empty/demo/live builds. Chrome acceptance covers 390/768/1440 pixels, source/evidence/search/register/ATT&CK/archive controls, unchanged KEV values, bar labels and nonvisual description, absence of the chart table/header timestamp, full compact radar wording including abbreviations, license-dialog content/focus/overflow, and unavailable-data behavior without browser errors. Desktop and mobile screenshots were visually inspected. The page height falls from 1,948 to 1,663 pixels on desktop and from 3,112 to 2,670 pixels on phone.

The footer now contains GitHub and Sources & Licenses. SANS credit, supplied bylines, original links, adaptation notice and CC BY-NC-SA obligations remain available; MITRE’s reproduction notice accompanies catalog context and its full license is included in the dialog and build. Publisher rights and the font license remain. Placement was checked against the primary SANS, Creative Commons and MITRE terms linked in [publication documentation](publication.md#reader-attribution-and-chart-access). Weekly identity, source evidence, original publication time and history are preserved through the explicit revision path.


## Final interactions and editorial illustration — 2026-11-12

The current 114-word executive summary, every accepted edition and all source/STIX records remain unchanged. Schema 7 adds a source-bound illustration cache; one original cloud/chip/key/cost-arrow SVG accompanies the November 2–9 lead on desktop. It uses about 32% of the reading row and is omitted on narrow phones. An existing local Ollama SVG trial completed at the 800-token length bound and returned invalid XML. Production therefore uses the requested original-composition library fallback, not accepted model SVG. New assets are subject-selected once, cached per approved weekly lead, revalidated and emitted as static files. Unknown subjects or invalid new artwork omit the image without disrupting publication. No new model, service, paid API or dependency is required.

Local verification passes 143 Python tests, 35 Node tests, infrastructure/repository checks and empty/demo/live builds. New cases cover safe geometry, active-content/resource/reference/XML rejection, size/complexity limits, cache reuse without regeneration, unsupported subjects, invalid-generation omission, unchanged editorial text, schema-7 collection compatibility and exact static asset output. Chart record helpers share the existing deduplication/window algorithm; counts remain unchanged even with duplicate CVEs carrying different dates.

Chrome acceptance passes at 390/768/1440 and with actual mobile touch emulation. Checks include More/Less ordering and in-place keyboard focus, hover/keyboard/touch chart records and full lists, viewport bounds, CVE details, inside/outside/X/Escape modal behavior, background scroll lock and focus restoration, retained source/license information, source relationships, search, weekly-only archive sorting/deduplication and historical artwork association. Current public data has no previous weekly editions, so the public archive shows a minimal empty state. Its legacy technical records remain searchable and retained in JSON. Desktop/mobile renderings were inspected visually.

The GoldFinder→Internet Connection Discovery relationship was inspected in the original local STIX version and fetched again from MITRE TAXII. Its source `modified` is April 29, 2026; source creation is March 26, 2021. The malware and technique objects have separate 2025 modification dates. First local collection was November 11, 2026. The frontend now labels the date Relationship modified; no synchronization clock or entity timestamp was substituted. [Exact fields and source endpoint](publication.md#relationship-date-investigation).
