<h1 align="center">EMBER · Threat Intelligence Observatory</h1>

<hr>

<p align="center"><strong>MISP · OpenCTI · Ollama · Automated Threat Intelligence</strong></p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/Python-3.11%2B-ff875a?style=flat-square&amp;labelColor=252522">
  <img alt="Local inference" src="https://img.shields.io/badge/Inference-local_Ollama-ff875a?style=flat-square&amp;labelColor=252522">
  <img alt="GitHub Pages hosting" src="https://img.shields.io/badge/Hosting-GitHub_Pages-ff875a?style=flat-square&amp;labelColor=252522">
  <img alt="Python standard library runtime" src="https://img.shields.io/badge/Runtime-Python_standard_library-ff875a?style=flat-square&amp;labelColor=252522">
</p>

<p align="center">Public threat signals become private, correlated evidence and daily source-grounded briefs.<br>A separate publication boundary brings the safe results to a public intelligence dashboard.</p>

<p align="center">
  <a href="https://bran-dot-flake.github.io/STIX-TAXII-Threat-Intel-Automated-Summary/">Live Observatory ↗</a> ·
  <a href="#overview">Overview</a> · <a href="#objectives">Objectives</a> ·
  <a href="#architecture">Architecture</a> · <a href="#implementation">Implementation</a> ·
  <a href="#results">Results</a> · <a href="#setup">Setup</a>
</p>

<hr>

## Overview

EMBER is an automated threat intelligence publication backed by a private Ubuntu lab. It brings together exploited-vulnerability catalog entries, public indicators, security advisories, and structured MITRE ATT&CK® knowledge. Readers get a compact daily brief, source-linked stories, useful trends, searchable CVEs, and historical editions on one static page.

The lab uses MISP to organize source-attributed observations, OpenCTI to represent intelligence entities and relationships, and an existing local Ollama model to select relevant source excerpts. A separate exporter publishes only validated public-source data. GitHub Pages remains available while the collector or model is offline.

## Objectives

- Automate collection without losing source attribution, object versions, or the distinction between catalog updates and observed attacks.
- Demonstrate real STIX 2.1 parsing and TAXII 2.1 discovery, collection retrieval, pagination, and incremental synchronization.
- Verify MISP/OpenCTI writes with independent read-back and durable checkpoints.
- Use local inference for evidence-grounded briefs while deterministic code supplies counts, relationships, and publication selection.
- Keep the reading experience compact and the private lab outside the public hosting boundary.

## Architecture

```mermaid
flowchart TB
  Feeds[CISA + CIRCL] --> Python[Python normalization]
  subgraph Lab[Private Ubuntu lab]
    Python --> State[SQLite checkpoints]
    State --> MISP[MISP]
    MISP --> Connector[Official MISP connector + CVE bridge]
    Connector --> OpenCTI[OpenCTI]
    MISP --> Verify[Evidence verification]
    OpenCTI --> Verify
    Verify --> Ollama[Local Ollama]
    Ollama --> Brief[Validated daily brief]
    TAXII[TAXII 2.1 / local STIX bundle] --> STIX[Versioned STIX store]
    STIX --> Bridge[Optional catalog API bridge]
    Bridge --> OpenCTI
    Timer[Daily systemd timer] --> Python
    Timer --> TAXII
  end
  Feeds --> Public[Original-source export]
  Brief --> Public
  STIX --> Gate[Source + marking + license gate]
  Gate --> Public
  Public --> JSON[Sanitized JSON / intel-data branch]
  JSON --> Actions[GitHub Actions]
  Actions --> Pages[Static GitHub Pages publication]
```

The feed/reporting path and STIX store are independent. MISP continues to own the existing IOC workflow. The optional STIX bridge imports approved MITRE catalog entities directly into OpenCTI; it does not force structured catalog objects into MISP events or introduce an always-running connector.

## Implementation

### Collection and evidence

The private pipeline collects CISA KEV additions from the last fourteen days and a bounded CIRCL public OSINT sample: three recently modified events with up to twenty supported attributes each. Stable MISP UUIDs and native OpenCTI upserts reconcile retries. The official MISP connector handles indicators/observables; a CVE-only API bridge fills its standalone vulnerability gap. Strict reporting verifies exact values and MISP provenance, rather than treating search candidates as proof.

The public exporter independently recollects up to ninety days of KEV additions, the bounded public CIRCL sample, and CISA advisory RSS. Editorial selection reserves room for distinct advisories instead of filling the feed with near-identical KEV bulletins. Related catalog updates are grouped, exact duplicate headlines are consolidated, and each original source link remains accessible. Introductory source sentences replace clipped CVE lists where possible.

KEV dates mean catalog additions, not exploitation or disclosure dates. IOC first-collected times are publication baselines, not attack occurrence. MITRE catalog modifications are knowledge-base updates, not daily threat events.

### STIX 2.1 and TAXII 2.1

The optional integration uses OASIS's `stix2` and `taxii2-client` libraries. Live discovery selects MITRE's Enterprise ATT&CK collection. Three bounded streams retrieve entities/observables, relationships, and identity/marking definitions. Common SDOs, SCOs, report object references, custom extensions, source STIX IDs, and original JSON remain in a separate SQLite store. Local bundle import uses the same parser without requiring a network or platforms.

SDO versions are keyed by source, STIX ID, and normalized modification timestamp. Exact repeats deduplicate; conflicting content at the same version fails closed. Unversioned observable variants retain content hashes and insertion order without invented modification dates. Latest active views exclude revoked/deprecated objects, while historical payloads remain available.

Each accepted page and its continuation token commit atomically. A bounded run resumes at its saved cursor; the incremental date-added checkpoint advances only after the complete traversal. Equal-timestamp overlap is deduplicated. Page-size/filter changes and changes to discovered release roots trigger bounded replay. Expired cursors queue replay from the previous safe watermark. This matters because MITRE can expose old date-added values for recently modified catalog content.

Transport uses TLS, same-origin endpoint checks, no redirects, bounded responses, timeouts, retries, and `Retry-After` handling. A persistent 35-request/ten-minute budget leaves headroom beneath [MITRE's documented rate limit](https://raw.githubusercontent.com/mitre-attack/attack-workbench-taxii-server/main/docs/USAGE.md). Optional basic or bearer credentials come from the private environment and never enter exported JSON or logs. [Full ingestion contract](docs/stix-taxii.md).

The OpenCTI catalog bridge supports attack patterns, intrusion sets, malware, tools, and their resolved source relationships. Native upserts preserve source STIX IDs and source references. Entity names/IDs and relationship types/endpoints are read back before checkpointing. It is an active catalog projection, not a complete replacement for OpenCTI's general STIX importer. Local storage retains metadata and lifecycle history beyond that projection.

### Briefing and publication

Ollama chooses and orders complete source excerpts tied to evidence IDs. JSON-schema constraints and independent local validation reject unsupported text, IDs, duplicates, and extra fields. Free-form synthesis cannot be checked by the existing exact-evidence validator, so the website uses a deterministic multi-finding overview with clearly identified source excerpts. No additional model call is needed for publication.

Up to eight observations are briefed per run. Failed inference produces a marked fallback, exits 2, and retains the retry queue. Successful reports exit 0; other core failures exit 1. Quiet days are explicit. The resource-aware orchestrator prepares verified evidence with the platforms running, stops only this project's containers for CPU inference, then restores the selected resident profile. [Synthetic report](examples/daily-brief.synthetic.md).

Public brief promotion requires exact independently recollected record versions and the batch digest. CIRCL event/object/attribute restrictions are checked and indicators defanged. STIX publication is limited to the reviewed original MITRE source and resolved permissive markings/license; local bundles and private TAXII feeds remain private. Only resolved, active source relationships enter the small public catalog. No actor/technique relationship is inferred from a headline or by the model.

The publisher writes one validated JSON file to `intel-data`, never stages the working tree or exports a token, and never force-pushes. Actions validates again and copies an asset allowlist. Individual source failures preserve accepted data and original success times. The frontend is plain HTML/CSS/JavaScript with same-origin assets, no framework/CDN, and no lab connection. [Public data contract](docs/publication.md).

## Results

[Open EMBER](https://brandonchaney.dev/STIX-TAXII-Threat-Intel-Automated-Summary/).

![Compact EMBER daily brief, statistics, trends, and editorial intelligence](docs/images/dashboard-desktop.png)

<details>
<summary>Phone layout</summary>

<img src="docs/images/dashboard-mobile.png" alt="Single-page EMBER at phone width" width="320">

</details>

The current frontend removes the permanent sidebar, introductory masthead, standalone status view, and separate report/CVE pages. Brief, trends, grouped stories, vulnerabilities, and archive share one page. The first brief shows up to three distinct findings; complete reports, catalog context, CVEs, and archived editions expand in place. Images are limited to one optional original illustration in the visible story grid.

The November 11, 2026 live TAXII acceptance stored **220 original STIX objects** across bounded/resumed requests. The accepted public projection contained **61 catalog objects and five resolved source relationships**. A real OpenCTI pilot read back catalog entities and relationships; an isolated three-object import repeated with **zero additional writes**. These are bounded acceptance samples, not complete Enterprise ATT&CK coverage.

The public feed snapshot also contained **114 KEV entries, 45 unique public IOCs, eighteen selected advisories, and two accepted briefs**. Those figures are dated evidence, not throughput or comprehensive coverage claims. The existing lab previously verified forty-one observations against MISP/OpenCTI and completed a real systemd-managed reporting run. [Validation evidence](docs/validation.md).

The expanded checks cover parsing, relationships, lifecycle/version handling, pagination, resumable and incremental cursors, expired tokens, rate limits, marking restrictions, public filtering, platform read-back, frontend calculations, and the existing reporting path. Browser checks exercise the single-page interactions at phone, tablet, and desktop widths. Synthetic and unavailable-data states remain explicit.

## Setup

Python **3.11+** runs the core feeds, reports, export, and static build without external runtime packages. STIX/TAXII adds two optional libraries and their dependencies. Node 24 runs the JavaScript calculation tests. Browser acceptance uses optional development-only Playwright. The complete lab also needs Docker Compose and an existing Ollama installation.

### Preview and test

```sh
export PYTHONPATH=src
python3 -m pip install '.[stix]'  # isolated environment recommended
python3 -m unittest discover -s tests -v
node --test tests/dashboard.test.mjs
python3 scripts/validate.py
python3 -m ti_brief.cli --demo
python3 scripts/build_dashboard.py --demo
python3 -m http.server 4173 --bind 127.0.0.1 --directory dist
```

Open `http://127.0.0.1:4173`. The demo is visibly synthetic and cannot reach the live publisher. Omit `--demo` for the empty state. Without optional STIX dependencies, its tests are explicitly skipped. In PowerShell, use `$env:PYTHONPATH='src'` and run Python commands separately.

### Synchronize STIX/TAXII

```sh
python3 -m venv work/stix-venv
work/stix-venv/bin/python3 -m pip install -r requirements-stix.lock
PYTHONPATH=src work/stix-venv/bin/python3 scripts/sync_taxii.py --discover
PYTHONPATH=src work/stix-venv/bin/python3 scripts/sync_taxii.py --sync
PYTHONPATH=src work/stix-venv/bin/python3 scripts/sync_taxii.py \
  --bundle tests/fixtures/mitre-taxii.sample.json --source example
```

Defaults use MITRE Enterprise ATT&CK, pages of 100 objects, up to two pages per main stream, one definition page, and twelve dependency lookups. Repeated runs resume. Use `--discovery`, `--root`, `--collection`, `--source`, and optional `--types` for another source; it remains private by default. [Configuration, authentication, checkpoints, and limits](docs/stix-taxii.md).

With the existing OpenCTI platform running, optionally enable its catalog bridge:

```sh
PYTHONPATH=src python3 scripts/sync_stix_opencti.py --max-objects 20
```

### Collect and publish

```sh
PYTHONPATH=src python3 scripts/export_publication.py
python3 scripts/build_dashboard.py --snapshot data/publication/snapshot.json
PYTHONPATH=src python3 scripts/export_publication.py --publish
```

Publishing needs existing `gh` authentication with repository/workflow access and **Pages → Source: GitHub Actions**. The data branch is isolated; relative assets and section anchors support project URLs. For a fork, update repository links and `TI_PUBLICATION_REPOSITORY`.

The approved timer runs daily at 08:00 UTC with up to five minutes of jitter. `TI_TAXII_ENABLED=true` adds bounded collection before reporting; `TI_STIX_OPENCTI_ENABLED=true` adds the optional bridge after platform restoration. `TI_PUBLICATION_ENABLED=true` exports/publishes afterward. No additional daemon, model download, firewall opening, or administrative unit is required. [Environment example](.env.example).

### Full lab and maintenance

```sh
python3 scripts/assess.py
python3 scripts/init_env.py
# Configure .env locally and select an already installed OLLAMA_MODEL.
PYTHONPATH=src python3 scripts/daily_staged.py --manage-project
```

Inspect resources before installation; consult [resource planning](docs/resources.md) and [incremental deployment](docs/deployment.md). The target has about 10 GiB guest RAM and CPU inference, below OpenCTI production sizing. `TI_RESIDENT_PROFILE=misp` is the conservative default; the optional graph bridge needs OpenCTI available. `all` is for an accepted combined pilot. Unrelated workloads remain outside the orchestrator's scope.

| Path | Responsibility |
| --- | --- |
| `src/ti_brief/feeds.py`, `model.py`, `store.py` | Source observations and reporting state |
| `src/ti_brief/stix_store.py`, `taxii.py` | Structured STIX ingestion and TAXII transport/checkpoints |
| `src/ti_brief/platforms.py`, `stix_platform.py` | Existing integrations and bounded catalog bridge |
| `src/ti_brief/report.py` | Ollama contract and private report rendering |
| `src/ti_brief/publication.py`, `stix_publication.py`, `publish.py` | Public projection and outbound publication |
| `website/`, `scripts/`, `deploy/` | Static interface, one-shot operations, locked lab configuration |
| `tests/`, `examples/`, `docs/` | Checks, labeled fixtures, and operating evidence |

Private state, reports, credentials, model files, and logs stay ignored. [SECURITY.md](SECURITY.md) describes the boundaries. Logs retain redacted stage/error classes and source health; a missing public brief is not a reason to bypass validation. Stale collection is marked unobtrusively on the site. The site stays accessible during a VM outage, but fresh collection requires the collector to return.

Broader source licensing policies, full Enterprise catalog bootstrap, general OpenCTI STIX import/retirement, and source-supported links between daily reports and ATT&CK remain extensions. The current implementation does not assign catalog techniques to unrelated CVEs or turn knowledge-base changes into attack reports.
