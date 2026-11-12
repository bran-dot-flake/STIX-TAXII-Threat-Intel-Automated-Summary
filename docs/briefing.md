# Briefing, grounding, and chronology

## Weekly publication

Daily collection refreshes the Latest Intelligence feed, search, vulnerability register, source health and statistics. The active public workflow in `executive.py` produces **weekly editions only**. It never promotes new private daily batches or creates interim articles. Historical batch and version-1/2 editions remain readable in the archive under their original validators.

The completed seven-day UTC window defaults to Monday 08:00 through the following Monday 08:00, half-open `[start, end)`. Configure `TI_WEEKLY_DAY` (Monday=0) and `TI_WEEKLY_HOUR_UTC`; the existing daily timer runs the next collection after that boundary. No additional service is needed. The first run may publish the latest completed window late, with its real publication time. It does not manufacture missed historical weeks. Accepted windows cannot overlap, and the same window ID cannot be published twice. A quiet or failed run retains the last accepted article.

The front page shows **Weekly Brief**, one compact period and one header update indicator. Exact evidence cutoff, original publication time, source publication/modification and any explicit revision time remain in the JSON and archive. A publication date is not an incident date.

## Evidence preparation

Only independently sanitized public projections enter editorial selection. Up to three distinct developments, four research records, 36 relevant catalog observations and eight explicitly referenced ATT&CK objects are retained. Firsthand incident/telemetry reporting, concrete consequences, measured changes and useful source detail precede simple recency. A familiar CVE phrase alone provides no priority. Marketing and event promotions do not qualify. Catalog-only editions require an explicit documented vulnerability chain; routine additions continue updating the register without forcing prose.

Exact report URLs and explicit matching CVE subjects support grouping. Microsoft Patch Tuesday reports can share a verified month/year release identity, retaining both publishers and their separate totals. Shared actor, vendor or technique names never establish a common campaign. Only healthy sources can trigger a new edition. Old material requires both an in-window source modification and a measured substantive change; a new collection clock is insufficient. Content modified after cutoff is excluded rather than reconstructed as an earlier version.

Reviewed structured fact notes in `editorial_approvals.json` can clarify exact source versions before inference. They carry source-content digests, dated qualifications and hashed evidence spans. Unknown or changed sources use their original bounded, untrusted excerpts. Notes are evidence preparation, not prewritten sentence options. Source assertions are not independently proven ground truth.

## Natural composition and independent review

The existing CPU-only Ollama receives selected evidence and writes a short headline, two or three cohesive overview paragraphs (target 200–300 words), and one concise radar sentence per development. It is free to paraphrase and organize ideas; the schema does not enumerate approved sentences. The prompt distinguishes attempts from compromise, publication from incident timing, assessed attribution from certainty, and thematic comparisons from shared campaigns. No paid API, extra model, package or service is required.

Mechanical checks reject unknown identifiers, unsupported numbers/scales, unrelated citations, extra fields, missing developments, long copied passages, repeated wording and generic filler. These are **not semantic entailment**. A valid evidence ID, word overlap or another model's approval cannot verify arbitrary English.

Novel prose therefore stays in ignored `data/editorial/review/` until explicit source review is recorded in the repository-owned registry. The writer cannot modify that registry. A receipt binds the exact plan and semantic evidence digest, each claim's text hash, review rationale and hashed source spans. Every cited source must have reviewed support. Review covers chronology, attribution, negation, uncertainty and interpretive conclusions as well as identifiers. The model cannot approve its own output. A reviewer must assess each actual claim; copying citations into a receipt is not an adequate review.

Origins are honest: `ollama-reviewed` means an unchanged reviewed model plan; `ollama-edited-reviewed` means a model proposal was revised and source-reviewed; `deterministic-fallback` means an explicitly reviewed editorial plan. Codex-assisted review is labeled as such, not as user or human approval. No receipt is generated automatically by the scheduler.

This conservative design limits fully unattended publication of **novel unrestricted analysis**: daily intelligence collection is automatic, but new free-form prose may need editorial review. An evidence-identical reviewed plan can be reused without inference as a readable fallback. If no acceptable reviewed prose exists, the last valid weekly stays visible; excerpt concatenation and empty daily articles are not substituted.

## Scheduled operation

```sh
PYTHONPATH=src python3 scripts/export_publication.py
PYTHONPATH=src python3 scripts/compose_brief.py --editorial
PYTHONPATH=src python3 scripts/export_publication.py --publish-prepared
```

Collection prepares the sanitized snapshot; composition skips already accepted windows, reuses reviewed plans and avoids repeated inference for an unchanged pending proposal. Explicit `--retry-draft` permits a deliberate retry. The model retains two threads, a 4,096-token context, bounded output, `keep_alive=0` and the 3,500 MiB available-memory guard. Failures log retention rather than publishing invented fallbacks. A prepared snapshot expires after 24 hours. Publication never recollects evidence between composition and commit. Checkpoints advance only after the data commit succeeds; a separate hosting-dispatch failure is reported.

An operator-requested correction can use `compose_brief.py --editorial --revise-latest` followed by `export_publication.py --publish-prepared --revise-latest`. This exceptional path uses the latest weekly's frozen source evidence, preserves its ID and original publication date, and records `revised_at`. Routine scheduled runs cannot revise accepted articles. Prior data commits retain earlier text; the archive does not add a duplicate week.

## November 12 diagnosis and correction

Both inspected CPU Ollama runs completed; the observed rejection was validation-related, not an assumed resource failure. One overview used story identifiers instead of required fact identifiers. Another attached lead IDs but failed the previous complete-sentence wording check. The old gate protected factual claims but prevented free paraphrase. Historical validators remain unchanged; version-3 editions use the new review-bound path.

Two new free-form trials were also withheld: the first lost an attribution qualification and copied source lists; the structured-note retry repeated wording and mischaracterized SSH password observations. The corrected 225-word November 2–9 briefing was edited and reviewed claim by claim. It is **not evidence that the small local model autonomously passed semantic verification**. The accepted source excerpts and model proposals remain separate from the final reviewed prose.

## Preserved batch evidence contract

The excerpt layer and narrative layer are separate. `report.py` still accepts only complete approved source excerpts bound to the exact record ID. `topics.py` groups evidence before selecting up to four topics/eight observations. Each CVE is a separate topic. Only the exact original CIRCL event URL groups indicators; names, broad categories, and shared feed URLs cannot create a relationship. Conflicting event headlines are withheld from narrative and retain reviewable technical evidence.

`narrative.py` builds a small typed fact ledger from those observations. Facts cover original KEV membership, recognized vulnerability-class descriptions, the source-reported event subject, documented evidence types, chronology, and original recommendations. KEV membership supports CISA's exploitation assessment, not a claim of current attacks or local exposure. Source headlines remain attributed assertions. Unrecognized vulnerability classes receive no invented paraphrase. ATT&CK catalog names never create an incident relationship.

The existing local model chooses and orders permitted factual formulations into an overview and topic summaries/significance. This is intentionally constrained composition: it can paraphrase using reviewed formulations, but cannot publish arbitrary analysis that software cannot reliably verify. The independent validator requires complete topic/claim coverage, exact fact-to-text binding, correct supporting IDs and headlines, and unchanged freshness. Duplicate/unknown claims, fabricated numbers/CVEs/actors/mitigations, extra fields, and unsupported prose fail. Matching a valid evidence ID is insufficient. Instruction-like source fields and conflicting titles withhold that topic from model input and narrative.

The public exporter recomputes the ledger from independently recollected source versions, checks the original batch digest and excerpt selections, reprojects all observations, and validates the candidate narrative again. The narrative binds its generation window and complete observation input by a separate digest. No private platform context or arbitrary generated text is copied. The static build repeats validation. Schema 3 retains schemas 1/2 as readable input; older public editions receive deterministic topic presentations without changing original report dates. An optional one-edition Ollama cache records its separate composition time.

There is no general-purpose semantic verifier or claim that source assertions are true. The protection is a narrow publishable claim language plus original-source provenance. If a model call fails or returns unsupported prose, that draft is discarded and the fact-cited deterministic fallback is used; it never becomes a public review draft. Failed exact-excerpt inference retains the existing degraded-report/retry behavior. Unknown source claims are not upgraded to verified analysis.

## Time and selection

The preserved private-batch and version-1 editorial reporting window is previous UTC midnight through generation, inclusive. Current public editions use the completed weekly window above; historical version-2 editions retain their original windows. Trend analysis uses seven or thirty UTC calendar days, independently of publication eligibility. Dates remain visible in expanded evidence.

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
