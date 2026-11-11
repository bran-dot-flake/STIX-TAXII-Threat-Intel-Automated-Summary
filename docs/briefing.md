# Briefing, grounding, and chronology

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

Normal staged reporting runs the excerpt and narrative calls while this project's containers are paused. Both calls reuse the existing model, two CPU threads, a 4,096-token context, bounded output, and `keep_alive=0`. `TI_NARRATIVE_ENABLED=false` skips only narrative inference. No extra service or model is installed.

For an existing public edition:

```sh
PYTHONPATH=src python3 scripts/compose_brief.py
PYTHONPATH=src python3 scripts/export_publication.py --publish
```

The one-edition cache lives in ignored `data/narrative/`. A changed input digest rejects a stale cache and falls back safely. The exporter never calls Ollama. Original report dates and accepted history remain intact.
