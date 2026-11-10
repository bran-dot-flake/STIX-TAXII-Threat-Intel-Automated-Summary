# Validation record

This file separates observed results from deployment candidates. No administrative installation, VM reset, existing-service reconfiguration or prompt-injection project edit was performed.

## Completed on 2026-11-10

- GitHub access verified for the provided public repository; initial content was a single README commit.
- SSH key authentication verified through the existing Windows `spare` alias as `vboxuser`.
- Read-only guest inspection verified Ubuntu, RAM/CPU/disk/swap, running services, loopback Ollama, installed model, lack of Docker, apt candidates and kernel setting.
- Windows memory inspection observed approximately 15.86 GiB physical RAM and 2.89 GiB available; no change to VirtualBox allocation.
- Reused the empty `~/Threat-Intelligence-Platform` checkout. Existing prompt-injection repositories, including uncommitted artifacts, were inspected only through Git status and preserved.
- Sixteen initial Python tests passed on the guest's Python 3.14.4. The suite subsequently expanded on Windows Python 3.13.15; final CI is authoritative for the current commit.
- Real collection of CISA KEV and bounded CIRCL OSINT completed on the VM: **41 source observations ingested into private SQLite**, without MISP/OpenCTI writes.
- Twelve container manifests resolved from public registries, Linux amd64 presence checked, and immutable digests recorded. No image layers or containers were installed on the VM.
- Offline synthetic report generation passed, with a clearly synthetic example committed under `examples/`.
- Tests exercise a local HTTP server for MISP create/update/read-back, OpenCTI GraphQL request shape, Ollama structured output, HTTP limits/redirect rejection, and complete report/checkpoint flow. These mocks are not live application acceptance.

The Feodo endpoint originally proposed did not exist. Its real CSV uses `dst_ip`, `dst_port` and `c2_status` fields. The source returned a March 2026 freshness timestamp during November assessment, so it remains **disabled by default** and an explicit freshness gate rejects stale data. It is not presented as current threat intelligence. CIRCL's source event dates can be historical even when records were recently modified; modification timestamps are kept distinct.

## Real-model test unresolved

A smoke test began using the existing local `llama3.2` model and current CISA records. New SSH connections subsequently timed out, and the user confirmed a VM crash. The cause is unconfirmed; no OOM diagnosis is established. No completed model result could be retrieved, so this is not passing inference. The revised smaller context/two-thread configuration still needs retesting after recovery. The agent did not kill processes, reboot the VM or modify host networking, and paused further SSH attempts at the user's request.

## Required acceptance before calling this operational

| Requirement | Current evidence / next validation |
| --- | --- |
| MISP collecting real intelligence | Python feed collection passed; Docker install and MISP API import/read-back pending |
| OpenCTI receiving MISP data | Official connector configured; real entity/provenance read-back pending |
| Investigable objects/relationships | UI/API verification pending; source-supported relationships only |
| Local LLM validated excerpts | Mock contract passed; real inference unresolved |
| Daily unattended operation | Reviewed user units and staged orchestrator prepared; not installed/enabled |
| Reliable within hardware | Baseline measured; live container/model peak/OOM/latency measurements pending |
| Reproducible configurations | Image lock and generated Compose validation implemented; live service compatibility pending |
| Secrets isolation | Ignore rules, exclusive 0600 initialization and redacted errors implemented; no actual lab secrets committed |

GitHub CI tests Python 3.11, 3.13 and 3.14, validates generated config against image locks, runs `docker compose config --quiet`, and exercises the offline demo. It does not start the full stack, access the private VM, ingest production data or validate real Ollama inference. Once a live stage is completed, append its measured evidence and any limitations here without turning startup checks into functional claims.
