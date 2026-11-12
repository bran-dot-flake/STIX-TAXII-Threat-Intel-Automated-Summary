# Briefing, grounding, and chronology

## Hybrid publication

Daily collection and editorial publication are separate. `hybrid.py` reviews only the independently collected public snapshot; it never imports arbitrary platform content. Data refreshes update the vulnerability register, search, source timestamps and deterministic trends even when no article is due.

The primary edition covers a completed **seven-day UTC window**. Defaults are Monday 08:00 UTC through the next Monday 08:00 UTC, with a half-open `[start, end)` interval. The next daily job after that boundary produces the weekly briefing. A first installation may publish the latest completed window later; the website displays both its actual publication date and covered interval. It does not backdate the article. Fixed window IDs and accepted history make reruns idempotent. Schedule changes cannot create an overlapping weekly edition. Missed historical weeks are not automatically backfilled.

Between weekly editions, the default 48-hour source-date window can produce a short interim update. Explicit CVE exploitation/attempt reports, documented vulnerability chains, or source-reported campaign/malware observations can qualify. Routine CVEs, generic product promotions, catalog bulletins and negated activity claims do not qualify alone. These are editorial thresholds, not severity scores or evidence of local compromise. The first detailed exploitation report about a previously cataloged CVE can qualify; another unchanged article about that same CVE does not automatically qualify.

Exact original URLs group report indicators. Vulnerability articles with explicit matching CVE subjects can share a topic; actor/vendor names alone cannot merge campaigns. Accepted editions retain content fingerprints and story identities. A source modification timestamp **and** a measured content change can qualify an older article; collection clocks and metadata-only refreshes cannot. Weekly retrospectives may revisit interim developments, labeled previously covered, without calling them newly discovered attacks.

Quiet collections create no editorial edition, do not invoke editorial Ollama, and do not replace a substantive briefing. Collection status and publication date are independent. The weekly edition stays prominent; a newer interim update is available in a compact expandable row. Legacy empty editions remain valid historical input but are hidden from the reader archive. New zero-record private batches are not promoted into public articles.

## Selection and composition

Selection is bounded to 36 public observations, four research/advisory records and eight explicitly cited ATT&CK references. Source diversity precedes remaining report selection, after significance and source-date gates. Marketing, podcast and conference items are excluded. Report dates, first collection, measured content changes, explicit modification and historical context remain distinct. An old report fetched today is not a new development. Source failures retain earlier accepted data and articles; only successfully checked sources can trigger new editorial work.

Weekly prose targets **300–450 words across overview and developments**, when the selected evidence supports that length. Shorter evidence produces a shorter edition. Interim editions are capped at 240 words. The executive overview uses actual source findings; their remaining context appears under the developments instead of repeating the same description. Attribution dates anchor relative phrases such as “last week.” Defensive review steps are explicitly editorial suggestions, not claims of local exposure or publisher endorsement.

`editorial.py` retains the existing independent claim gate. The local model selects and arranges source-cited, meaning-preserving formulations; names, numbers, negation, conditions and uncertainty must remain supported. Arbitrary paraphrases, inferred actor/technique relationships and a second model's opinion are not treated as entailment. Unsupported overview prose is withheld. Unsupported supporting prose is replaced with a checked source summary, and the complete final plan is validated again. Rejected drafts stay in ignored `data/editorial/review/`. This remains a bounded claim language, not a general semantic verifier.

Schema 5 adds collection state and version-2 hybrid editions, preserving legacy schema 1–4 and version-1 editorial validators. Each accepted edition binds its reporting window, public evidence, deterministic topics, continuity state and checked prose by digest. Historical input is copied, never aliased to mutable live rows. The evidence cutoff and actual publication timestamp are separate, including across UTC midnight. An accepted publication date is immutable. Local editorial checkpoints advance only after the public data commit succeeds; a hosting-dispatch failure is separately reported.

## Scheduled operation

The existing daily systemd timer and private MISP/OpenCTI/STIX stages remain. Configure publication through `TI_WEEKLY_DAY` (Monday=0), `TI_WEEKLY_HOUR_UTC` and `TI_UPDATE_LOOKBACK_HOURS`; defaults are `0`, `8`, `48`. These are application settings; no new system timer or service is installed.

```sh
PYTHONPATH=src python3 scripts/export_publication.py
PYTHONPATH=src python3 scripts/compose_brief.py --editorial
PYTHONPATH=src python3 scripts/export_publication.py --publish-prepared
```

Collection prepares a fixed public snapshot. Composition skips if nothing qualifies, reuses a matching checked cache on retries, and otherwise reuses the installed CPU Ollama model with two threads and a 4,096-token context. The 3,500 MiB available-memory guard and unload request remain. Unavailable inference uses the independently checked fallback. Prepared publication expires after 24 hours and never recollects evidence between composition and commit. Immediate `--publish` remains a deterministic-fallback path. Private excerpt generation remains independent.

## Preserved batch evidence contract

The excerpt layer and narrative layer are separate. `report.py` still accepts only complete approved source excerpts bound to the exact record ID. `topics.py` groups evidence before selecting up to four topics/eight observations. Each CVE is a separate topic. Only the exact original CIRCL event URL groups indicators; names, broad categories, and shared feed URLs cannot create a relationship. Conflicting event headlines are withheld from narrative and retain reviewable technical evidence.

`narrative.py` builds a small typed fact ledger from those observations. Facts cover original KEV membership, recognized vulnerability-class descriptions, the source-reported event subject, documented evidence types, chronology, and original recommendations. KEV membership supports CISA's exploitation assessment, not a claim of current attacks or local exposure. Source headlines remain attributed assertions. Unrecognized vulnerability classes receive no invented paraphrase. ATT&CK catalog names never create an incident relationship.

The existing local model chooses and orders permitted factual formulations into an overview and topic summaries/significance. This is intentionally constrained composition: it can paraphrase using reviewed formulations, but cannot publish arbitrary analysis that software cannot reliably verify. The independent validator requires complete topic/claim coverage, exact fact-to-text binding, correct supporting IDs and headlines, and unchanged freshness. Duplicate/unknown claims, fabricated numbers/CVEs/actors/mitigations, extra fields, and unsupported prose fail. Matching a valid evidence ID is insufficient. Instruction-like source fields and conflicting titles withhold that topic from model input and narrative.

The public exporter recomputes the ledger from independently recollected source versions, checks the original batch digest and excerpt selections, reprojects all observations, and validates the candidate narrative again. The narrative binds its generation window and complete observation input by a separate digest. No private platform context or arbitrary generated text is copied. The static build repeats validation. Schema 3 retains schemas 1/2 as readable input; older public editions receive deterministic topic presentations without changing original report dates. An optional one-edition Ollama cache records its separate composition time.

There is no general-purpose semantic verifier or claim that source assertions are true. The protection is a narrow publishable claim language plus original-source provenance. If a model call fails or returns unsupported prose, that draft is discarded and the fact-cited deterministic fallback is used; it never becomes a public review draft. Failed exact-excerpt inference retains the existing degraded-report/retry behavior. Unknown source claims are not upgraded to verified analysis.

## Time and selection

The preserved private-batch and version-1 editorial reporting window is previous UTC midnight through generation, inclusive. Hybrid public editions use the separate weekly and interim windows above. Trend analysis uses seven or thirty UTC calendar days, independently of publication eligibility. Dates remain visible in expanded evidence.

| Classification | Required evidence |
| --- | --- |
| Catalog addition | Original KEV `dateAdded` falls in the window |
| New publication | Original source publication falls in the window |
| Source updated | Source modification **and** locally recorded substantive content change fall in the window |
| Newly collected · historical | First collection is in the window; known source publication/modification is older |
| Historical context | Known source dates are older; collection is earlier or unknown |
| Publication date unavailable | No usable source publication/modification date |

Local collection is never an attack occurrence. CIRCL publish timestamps describe the feed event publication, not necessarily the underlying campaign's age. Source modification clocks alone cannot prove a meaningful update. Editorial content fingerprints exclude publication/modification/occurrence clocks; changing only those clocks keeps the report checkpoint while the original source version continues through MISP/OpenCTI synchronization. Existing databases migrate conservatively: missing past substantive-change evidence is not reconstructed.

The selector scans at most 500 pending records, ranks actual source freshness before historical material, reserves one observation per selected topic, then fills remaining slots with their evidence. This bounded sample is not complete feed coverage. Quiet editions explicitly report no supported selected development; historical backlog remains labeled as context, never breaking activity. STIX/TAXII context stays available separately; only original supported relationships are shown, without attaching techniques/actors to a brief by name matching.

## Operations

When public publication is disabled, private staged reporting runs excerpt and batch-narrative calls while this project's containers are paused. The publication-enabled sequence is described above and performs editorial inference after resident-profile restoration. Both calls reuse the existing model, two CPU threads, a 4,096-token context, bounded output, and `keep_alive=0`. `TI_NARRATIVE_ENABLED=false` skips only narrative inference. No extra service or model is installed.

To retrofit an accepted legacy batch report:

```sh
PYTHONPATH=src python3 scripts/compose_brief.py
PYTHONPATH=src python3 scripts/export_publication.py --publish
```

The one-edition cache lives in ignored `data/narrative/`. A changed input digest rejects a stale cache and falls back safely. The exporter never calls Ollama. Original report dates and accepted history remain intact.
