# Assessment and resource plan

Read-only assessment on 2026-11-10, before installations or administrative changes. Development actually runs in a Windows Codex session with SSH to the Ubuntu guest, rather than inside VS Code Remote SSH as the original handoff assumed.

| Item | Observed |
| --- | --- |
| Windows host | Windows 11; 8 logical processors; 15.86 GiB physical RAM; 2.89 GiB available at sampling time |
| Host disk | Approximately 11.5 GiB free on C:; avoid large host image/model downloads |
| Guest | Ubuntu 26.04 LTS, x86_64, kernel 7.0.0-43-generic |
| Guest RAM | 9,481 MiB total; 7,325–7,341 MiB available; about 2,140 MiB in use before inference |
| Guest CPU and disk | 3 logical CPUs; 52 GiB root filesystem, 34 GiB free |
| Swap | None |
| Docker | Not installed; no running Docker daemon or Compose |
| Kernel setting | vm.max_map_count = 1,048,576; no change needed |
| Ollama | 0.40.16, active native service, loopback 11434; no loaded model before smoke test |
| Existing model | llama3.2:latest, local ID a80c4f17acd5, 2.0 GB on disk |
| Existing projects | Two LLM prompt-injection checkouts, including uncommitted work; untouched |
| Project directory | Existing empty `/home/vboxuser/Threat-Intelligence-Platform` Git repository; reused without changing other projects |
| Privileged package candidates | Ubuntu docker.io 29.1.3 and docker-compose-v2 2.40.3; not installed |

The desktop guest is running GNOME and several development processes. There is no evidence yet that moving Ollama to Windows improves performance: both placements share the same physical RAM, and the host currently has limited headroom. Keep the existing installation until comparable measurements justify a move. No model was downloaded or reconfigured.

## Experimental container budget

These are **hard maximums for a small lab, below OpenCTI's supported published sizing**, not measured requirements, reservations, or proof that startup will succeed. Upstream currently lists at least 8 GB for OpenCTI Core and 8 GB for search; this project intentionally tests a bounded small-data deployment and must report OOM/startup failures honestly. [OpenCTI requirements](https://docs.opencti.io/latest/deployment/overview/).

| Component | Limit MiB | Key tuning |
| --- | ---: | --- |
| MISP core | 1,024 | Two PHP FPM children; 256M per PHP process |
| MariaDB | 384 | 128M buffer pool, 40 connections |
| MISP modules | 256 | Only required service, no extra enrichment connectors |
| MISP Valkey | 128 | 64M dataset, no eviction |
| MISP nginx | 64 | Loopback HTTP through SSH |
| **MISP subtotal** | **1,856** | **1.81 GiB** |
| Elasticsearch | 1,536 | 768M fixed heap, one node, no replicas/ML |
| OpenCTI | 1,536 | 1,024M Node heap |
| OpenCTI Redis | 256 | 128M dataset, no eviction |
| RabbitMQ | 384 | 192MiB watermark, single Erlang scheduler |
| Silo S3 | 192 | S3-compatible dependency used by current upstream OpenCTI Compose |
| OpenCTI worker | 192 | One process |
| **OpenCTI subtotal** | **4,096** | **4.00 GiB** |
| MISP connector | 256 | One-way, five-minute interval, small searches |
| **Combined cap** | **6,208** | **6.06 GiB, excluding OS and Ollama** |

The combined cap plus a 1,024 MiB free-memory margin requires at least 7,232 MiB **available at startup**. The initial 7,325 MiB measurement leaves only 93 MiB beyond that gate. A changing desktop workload can therefore make the gate fail. The first deployment should start MISP alone, measure it, then OpenCTI alone, and attempt a combined pilot only when headroom permits. Do not shrink caps blindly to pass the gate. Redis will refuse writes at its dataset limit rather than evicting OpenCTI state; investigate backlog and retention if this happens.

CPU limits are per-container ceilings and do not add CPU capacity. Multiple components may contend for three guest threads. Docker swap allowances equal the RAM limit because there is no guest swap. The preflight requires at least 25 GiB free initially; monitor indexes and images because 34 GiB is a narrow starting disk budget. Do not prune unrelated Docker images or existing datasets.

## Staged daily operation

After manual application acceptance, `scripts/daily_staged.py --manage-project` can:

1. Verify that every existing `ti-lab` container carries this project's ownership label; refuse name conflicts.
2. Stop this project's containers without deleting volumes, then check measured free resources.
3. Start MISP, OpenCTI, one worker and the official MISP connector.
4. Collect, synchronize MISP, read it back, and wait up to 900 seconds for exact OpenCTI matches carrying the MISP event UUID.
5. Save an evidence snapshot and stop this project's containers before inference.
6. Render with the existing Ollama model, requesting immediate unload (`keep_alive: 0`).
7. On success, restart MISP alone for access during the day. OpenCTI remains stopped until requested.

Any preparation failure still stops the owned platform containers. A failed model leaves reports queued and does not restart MISP, so the failure is visible. There is no volume deletion, package installation, sudo, network change or model download in the orchestrator. Only enable it once real connector provenance and actual memory use have passed manual acceptance.

Run `python3 scripts/monitor.py --samples 20` during each pilot stage and save its private JSONL. Correlate available RAM, host physical headroom, Docker RSS/caps, swap, CPU pressure, OOM counts and API latency. The orchestrator's memory check does not measure the Windows host: check host headroom separately.

## Inference uncertainty

SSH stopped responding after the first real-model smoke test began, and the user confirmed that the VM crashed. **The cause is unconfirmed**; guest/host memory pressure is a hypothesis requiring logs and measurements. The inference result and subsequent VM state could not be retrieved. Do not treat this as a successful LLM test. The repository subsequently reduced context to 4,096 tokens, limited inference to two threads, and bounded input/output; that revised configuration still needs a real VM retest. No reboot, process kill, Ollama service change or VirtualBox setting change was attempted. Further SSH attempts are paused at the user's request until they confirm recovery.
