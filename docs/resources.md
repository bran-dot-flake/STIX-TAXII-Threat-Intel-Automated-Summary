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
| MISP modules | 512 | Measured at about 399 MiB; 256 MiB caused container OOMs |
| MISP Valkey | 128 | 64M dataset, no eviction |
| MISP nginx | 64 | Loopback HTTP through SSH |
| **MISP subtotal** | **2,112** | **2.06 GiB** |
| Elasticsearch | 1,536 | 768M fixed heap, one node, no replicas/ML |
| OpenCTI | 1,536 | 1,024M Node heap |
| OpenCTI Redis | 256 | 128M dataset, no eviction |
| RabbitMQ | 384 | 192MiB watermark, single Erlang scheduler |
| Silo S3 | 192 | S3-compatible dependency used by current upstream OpenCTI Compose |
| OpenCTI worker | 192 | One process |
| **OpenCTI subtotal** | **4,096** | **4.00 GiB** |
| MISP connector | 256 | One-way, five-minute interval, small searches |
| **Combined cap** | **6,464** | **6.31 GiB, excluding OS and Ollama** |

The revised combined cap plus a 1,024 MiB free-memory margin requires at least 7,488 MiB **available at startup**. This exceeds the original 7,325 MiB baseline but fits the recovered VM's approximately 9,067 MiB. The first deployment starts MISP alone, measures it, then OpenCTI alone, and attempts a combined pilot only when headroom permits. Do not shrink caps blindly to pass the gate. Redis will refuse writes at its dataset limit rather than evicting OpenCTI state; investigate backlog and retention if this happens.

CPU limits are per-container ceilings and do not add CPU capacity. Multiple components may contend for three guest threads. Docker swap allowances equal the RAM limit because there is no guest swap. The preflight requires at least 25 GiB free initially; monitor indexes and images because 34 GiB is a narrow starting disk budget. Do not prune unrelated Docker images or existing datasets.

## Staged daily operation

After manual application acceptance, `scripts/daily_staged.py --manage-project` can:

1. Verify that every existing `ti-lab` container carries this project's ownership label; refuse name conflicts.
2. Stop this project's containers without deleting volumes, then check measured free resources.
3. Start MISP, OpenCTI, one worker and the official MISP connector.
4. Collect, synchronize MISP, read it back, and wait up to 900 seconds for exact OpenCTI matches carrying the MISP event UUID.
5. Save an evidence snapshot and stop this project's containers before inference.
6. Render with the existing Ollama model, requesting immediate unload (`keep_alive: 0`).
7. On success, restore MISP by default, or both platforms when `TI_RESIDENT_PROFILE=all` follows a measured combined pilot. The recovered target uses `all`.

Any preparation failure still stops the owned platform containers. A failed model leaves reports queued and does not restore the platforms, so the failure is visible. There is no volume deletion, package installation, sudo, network change or model download in the orchestrator. The complete staged job has passed live acceptance, including provenance and restoration of both UIs.

Run `python3 scripts/monitor.py --samples 20` during each pilot stage and save its private JSONL. Correlate available RAM, host physical headroom, Docker RSS/caps, swap, CPU pressure, OOM counts and API latency. The orchestrator's memory check does not measure the Windows host: check host headroom separately.

## Inference uncertainty

SSH stopped responding after the first model test and the user confirmed a VM crash. **Its cause is unconfirmed.** That test did not pass. After recovery, context was reduced to 4,096 tokens, inference limited to two threads and a 64-token prompt batch, and exact source choices enforced by schema and validation. Real two-record and eight-record staged reports then passed in approximately 22 and 46 seconds, with platform containers stopped and automatic model unload. No reboot, Ollama service change or VirtualBox setting change was performed by the agent.

## Recovery reassessment

The user expanded guest RAM/disk and closed the other VMs. Read-only checks after recovery on 2026-11-10 observed **10,260 MiB total RAM, 9,067 MiB available, three CPU threads, and 135 GiB free on the expanded 158 GiB root filesystem**. Swap remains absent. The revised 6,464 MiB container cap plus 1,024 MiB margin passes preflight with approximately 1,579 MiB beyond that gate at sampling time. This still does not establish simultaneous model/platform reliability.

The recovered host had approximately 2.83 GiB physical RAM available. The guest journal from the interrupted boot contained no retrieved OOM/panic evidence near the failure; logs ended without a conclusive cause. All 23 automated tests passed on the recovered guest. The user explicitly approved Docker package installation/service startup and separately approved Docker-group membership for `vboxuser`. Docker 29.1.3 and Compose 2.40.3 were subsequently observed installed and active; container acceptance remains a separate validation step.

The first MISP pilot recorded Docker OOM events in the modules container at 256 MiB. Raising that single limit to 512 MiB produced a stable approximately 399 MiB process with zero restarts in the new container. After bootstrap, the core used about 187 MiB, MariaDB 261 MiB, Valkey 4 MiB and nginx 5 MiB. Eight live CISA observations were imported and read back successfully. The initial nginx probe used an unavailable `wget`; it was corrected to the image's installed `curl`, and all five services became healthy. These are small-batch measurements, not long-term capacity benchmarks.

The combined pilot verified all 41 observations and completed the entire staged job. On 2026-11-11 all 12 containers were still up after about 16 hours, with approximately 6 GiB guest memory available. See [validation](validation.md) for detailed evidence and remaining acceptance.
