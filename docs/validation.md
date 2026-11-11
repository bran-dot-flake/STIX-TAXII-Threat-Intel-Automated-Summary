# Validation record

This record separates application acceptance from container startup and records failures as well as passing checks. Existing prompt-injection repositories and their uncommitted artifacts were preserved. The agent did not reboot the VM or modify its networking, swap, or Ollama service configuration.

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

The current 28-test suite passes locally. It covers normalization, stale feeds, bounded CIRCL parsing, deduplication, priority/backlog handling, nondestructive migration, MISP HTTP contracts, CVE upserts, exact OpenCTI provenance, model validation, secrets, snapshot expiry, locks and failed-run checkpoints. CI checks Python 3.11/3.13/3.14, Compose consistency, image locks, Compose syntax and the offline demo. An earlier 23-test commit passed [all jobs](https://github.com/bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary/actions/runs/42893100816). Consult current-commit checks for the expanded suite.

## Daily system service accepted on 2026-11-11

The owner explicitly approved and installed the reviewed system service/timer. The service executes as `vboxuser` with the approved Docker group. A real systemd-managed run completed with `Result=success`, `ExecMainStatus=0` and no retries, restored both platform UIs, and unloaded Ollama. It took 6 minutes 20.858 seconds overall and recorded a 48.3 MiB orchestration-process memory peak. Its eight-record inference/reporting phase took 103.78 seconds and wrote `reports/live/2026-11-11T132554.705191Z-run-12.md`. Twenty-three observations remained queued afterward; all 41 historical observations were retained even though two aged out of the feed's current collection window.

The timer is enabled for daily 08:00 UTC with up to five minutes of jitter, independent of interactive logins. The next observed activation was 2026-11-12 at 08:04:05 UTC (03:04:05 US Eastern). Missed executions are persistent; failures retry after 15 minutes, bounded to three starts in six hours.

Backup restoration, larger datasets, TAXII support and broader threat-entity feeds remain extensions. This is a functional small-data lab below OpenCTI's published production memory recommendations.
