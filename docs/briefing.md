# Briefing, grounding, and chronology

## Publication-wide editorial edition

`editorial.py` builds the front-page edition from the independently collected public snapshot, not the private report queue. It considers source-dated KEV additions and advisories, original CIRCL events, proven substantive updates from accepted evidence, and explicitly cited historical CVEs/ATT&CK identifiers. It never imports arbitrary MISP/OpenCTI content across the public boundary. The configured source mix remains limited; the overview describes available feeds, not all cybersecurity activity.

Curated input is bounded to 24 current observations plus four explicitly referenced historical records/eight proven updates, four source advisories, and eight catalog references. A same-date catalog story retains separate CVEs, while a possible vulnerability chain requires an explicit source `can be chained with CVE-…` statement. An authenticated-administrator/root-execution description does not become an unauthenticated exploit claim. CIRCL indicators group only through their original event URL; conflicting titles and recognized source instructions withhold that story. Historical collection alone does not create an editorial topic.

The model drafts source-cited sentence claims and concise supporting summaries, with a two-paragraph overview targeting roughly 120–170 words. Its JSON text is not an enum of two allowed sentences. The independent publication gate still requires complete source formulations or reviewed source-derived facts: all names, numbers, negation, conditions, uncertainty, and word order must remain supported. Punctuation/case variation and concatenation of complete facts are allowed; similarity scores, valid IDs, or a second model's opinion are not treated as entailment. This is a bounded claim language, not a reliable verifier of arbitrary free-form prose.

Checked sentences are arranged into developments first and supported significance/guidance second. An unsupported overview is withheld in full. An unsupported radar summary is replaced with the independently derived source summary while the checked overview can survive; the complete final plan is validated again. Raw rejected drafts remain in ignored `data/editorial/review/` and never enter the public schema. This permits useful model selection/composition without quietly accepting an unsupported paraphrase.

Public schema 4 retains the original batch reports and adds one self-contained editorial edition per UTC day, up to ninety days. Each edition binds its curated original public evidence, collection cutoff/reporting window, deterministic topics, source references, and final plan by a digest. The current edition must exactly match a fresh curation of the publication; historical editions keep their original accepted evidence. The expanded report exposes all supporting CVEs/IOCs, original descriptions, source/collection dates, recommendations, and explicit catalog references. A rerun replaces that day's edition instead of fabricating another historical date.

Daily staged publication collects/export-validates once, composes from that fixed snapshot, and invokes `--publish-prepared` to publish without recollecting or changing the evidence digest. Prepared snapshots expire after 24 hours. Staged operation skips the redundant private-batch narrative while preserving its exact-excerpt inference. Editorial inference runs after resident-profile restoration, checks at least 3,500 MiB available memory, reuses the existing CPU model/two threads, and requests unload. Low memory or unavailable Ollama publishes the checked fallback; no new service/model/package is needed.

```sh
PYTHONPATH=src python3 scripts/export_publication.py
PYTHONPATH=src python3 scripts/compose_brief.py --editorial
PYTHONPATH=src python3 scripts/export_publication.py --publish-prepared
```

## Preserved batch evidence contract

The excerpt layer and narrative layer are separate. `report.py` still accepts only complete approved source excerpts bound to the exact record ID. `topics.py` groups evidence before selecting up to four topics/eight observations. Each CVE is a separate topic. Only the exact original CIRCL event URL groups indicators; names, broad categories, and shared feed URLs cannot create a relationship. Conflicting event headlines are withheld from narrative and retain reviewable technical evidence.

`narrative.py` builds a small typed fact ledger from those observations. Facts cover original KEV membership, recognized vulnerability-class descriptions, the source-reported event subject, documented evidence types, chronology, and original recommendations. KEV membership supports CISA's exploitation assessment, not a claim of current attacks or local exposure. Source headlines remain attributed assertions. Unrecognized vulnerability classes receive no invented paraphrase. ATT&CK catalog names never create an incident relationship.

The existing local model chooses and orders permitted factual formulations into an overview and topic summaries/significance. This is intentionally constrained composition: it can paraphrase using reviewed formulations, but cannot publish arbitrary analysis that software cannot reliably verify. The independent validator requires complete topic/claim coverage, exact fact-to-text binding, correct supporting IDs and headlines, and unchanged freshness. Duplicate/unknown claims, fabricated numbers/CVEs/actors/mitigations, extra fields, and unsupported prose fail. Matching a valid evidence ID is insufficient. Instruction-like source fields and conflicting titles withhold that topic from model input and narrative.

The public exporter recomputes the ledger from independently recollected source versions, checks the original batch digest and excerpt selections, reprojects all observations, and validates the candidate narrative again. The narrative binds its generation window and complete observation input by a separate digest. No private platform context or arbitrary generated text is copied. The static build repeats validation. Schema 3 retains schemas 1/2 as readable input; older public editions receive deterministic topic presentations without changing original report dates. An optional one-edition Ollama cache records its separate composition time.

There is no general-purpose semantic verifier or claim that source assertions are true. The protection is a narrow publishable claim language plus original-source provenance. If a model call fails or returns unsupported prose, that draft is discarded and the fact-cited deterministic fallback is used; it never becomes a public review draft. Failed exact-excerpt inference retains the existing degraded-report/retry behavior. Unknown source claims are not upgraded to verified analysis.

## Time and selection

The reporting window is previous UTC midnight through report generation (24–48 hours depending on run time), inclusive. The regular 08:00 UTC edition therefore covers 32 hours, allowing modest collection overlap. Dates remain visible in expanded technical evidence.

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
