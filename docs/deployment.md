# Incremental deployment and operations

All commands run from the repository root in `/home/vboxuser/Threat-Intelligence-Platform`. Read [resources](resources.md) first. Existing prompt-injection checkouts and Ollama data must remain untouched. Do not run the complete stack merely because Compose parses.

## Approval boundary

The user's instruction explicitly requires approval before administrative changes. None have been performed. The proposed first administrative step is to install Ubuntu's `docker.io` and `docker-compose-v2` packages and enable/start Docker. Review `apt-get --simulate install --no-install-recommends docker.io docker-compose-v2` first; do not accept removals or unrelated upgrades. No third-party apt repository or shell-piped installer is needed.

After explicit approval, an operator can use:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends docker.io docker-compose-v2
sudo systemctl enable --now docker
```

Adding `vboxuser` to the `docker` group would grant root-equivalent daemon access and is a separate administrative choice. Do not silently add the group membership. Until that is approved, run manual Docker commands with authorized `sudo`; leave the user timer disabled. The staged scheduler requires noninteractive Docker access and must be enabled only after that choice is settled. Do not alter firewall rules, VirtualBox networking, kernel settings, swap or Ollama bindings as part of package installation.

## Configuration and inspection

```sh
python3 scripts/assess.py > assessments/ubuntu.json
python3 scripts/init_env.py
python3 scripts/validate.py
docker compose --env-file .env -f deploy/compose.json --profile misp --profile opencti --profile integration config --quiet
```

Create `assessments/` before redirecting output. `init_env.py` refuses to overwrite `.env`, generates fresh secrets without printing them, and aligns initial API keys with the bootstrapped administrators. Set `OLLAMA_MODEL=llama3.2:latest` only after verifying `ollama list` still identifies the expected installed model. Set `MISP_IMPORT_FROM_DATE` intentionally to limit historical import. No model or Python package installation is required for `PYTHONPATH=src` execution. Do not use unrestricted `docker compose config` in shared logs, because it expands secrets.

The image lock contains registry-verified Linux amd64 manifests for MISP v2.5.51, MISP modules v3.1.4, OpenCTI/worker/connector 7.261109.0, and pinned dependency images. OpenCTI's current upstream uses the Silo MinIO-compatible S3 service; the old MinIO Docker Hub artifact failed anonymous resolution. All final service references use digests. Image availability is distinct from application compatibility.

## First pilot: MISP only

```sh
python3 scripts/preflight.py misp
docker compose --env-file .env -f deploy/compose.json --profile misp pull
docker compose --env-file .env -f deploy/compose.json --profile misp up -d --no-build --wait --wait-timeout 900
```

From Windows, open a separate terminal with:

```sh
ssh -N -L 8081:127.0.0.1:8081 -L 8080:127.0.0.1:8080 spare
```

Visit MISP at `http://localhost:8081`; credentials remain in the private VM `.env`. Verify login, API `/servers/getVersion`, event creation and read-back using an isolated synthetic test event before a live import. Container TCP health alone is insufficient. Confirm named-volume persistence across a stop/start. Review `docker inspect` for `OOMKilled` and restart counts without dumping container environment variables. Measure resources using the read-only monitor. Stop MISP if needed with the same Compose file/profile and `stop`; never use `down -v`.

## Second pilot: OpenCTI only

Stop the owned MISP services before the first OpenCTI-only sizing test:

```sh
python3 scripts/preflight.py opencti
docker compose --env-file .env -f deploy/compose.json --profile opencti pull
docker compose --env-file .env -f deploy/compose.json --profile opencti up -d --no-build --wait --wait-timeout 900
```

Verify web login at `http://localhost:8080`, authenticated GraphQL `{ me { id } }`, search health and persistent storage. Confirm the installed GraphQL schema accepts the context query in `src/ti_brief/platforms.py`; the mock API tests do not validate a live schema. One worker is deployed. No optional XTM manager, Docker socket mount, ATT&CK bulk seed, enrichment connectors or mail relay is started.

## Combined integration pilot

Stop the owned pilot containers, check Windows physical memory, and run:

```sh
python3 scripts/preflight.py misp opencti integration
docker compose --env-file .env -f deploy/compose.json --profile misp --profile opencti --profile integration pull
docker compose --env-file .env -f deploy/compose.json --profile misp --profile opencti --profile integration up -d --no-build --wait --wait-timeout 900
PYTHONPATH=src python3 -m ti_brief.cli --prepare-only --max-records 2 --sync-timeout 900
```

The default feeds are CISA KEV and a small CIRCL OSINT sample. Events have deterministic UUIDs, organization-only distribution, `published=false` and `to_ids=false`; no blocking or external event sharing occurs. The MISP connector is deliberately configured to import unpublished private events, without attachments or guessed threats. It is the sole MISP-to-OpenCTI writer; there is no circular synchronization.

The prepare command writes at most 50 pending MISP records, reads back expected attributes, retrieves OpenCTI search candidates, and in strict mode requires an exact CVE/indicator match with an external reference containing the MISP event UUID. Verify this matches the actual connector's provenance representation. A search candidate or a running connector is not successful synchronization. If actual connector output uses another documented reference shape, update the verifier with a representative captured fixture and tests before enabling scheduling. Verify a repeated run creates no duplicates, a source change updates the existing event, and objects are queryable in the UI. The initial adapters do not invent actor/campaign relationships or ATT&CK techniques.

After a successful snapshot, stop the owned platform containers before inference, then:

```sh
PYTHONPATH=src python3 -m ti_brief.cli --render-prepared --max-records 2
```

The same `--max-records` bound must be used for prepare and render. Inspect the Markdown and JSON provenance, verify each cited source and timestamp, confirm no unsupported claims, and ensure Ollama `/api/ps` no longer lists the model after completion. A marked fallback is a degraded run, not acceptance. `scripts/smoke_ollama.py` independently tests real CISA + Ollama without claiming platform integration; it writes only `data/smoke` and `reports/smoke`.

## Daily scheduling, after acceptance

Once Docker access, real integration and staged inference are validated, an authorized user can install the reviewed user units:

```sh
mkdir -p ~/.config/systemd/user
cp deploy/ti-brief.service deploy/ti-brief.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user start ti-brief.service
systemctl --user enable --now ti-brief.timer
systemctl --user list-timers ti-brief.timer
journalctl --user -u ti-brief.service --since today
```

The unit references the inspected project directory. It invokes the explicit opt-in staged orchestrator, not an all-services-plus-LLM run. Containers must have the managed ownership label. The timer runs daily at 08:00 UTC, adds up to five minutes of jitter and catches up missed executions. A user service normally requires an active login; `loginctl enable-linger vboxuser` is an additional administrative change needing approval for unattended operation after logout/boot. The timer is not enabled by repository checkout or CI.

Exit 0 means a completed report, 1 means a feed/platform/operational failure, and 2 means degraded LLM reporting. Private SQLite `runs` records hold status, counts and elapsed time; monitor JSONL holds host/guest/container resource observations. Review failures in the journal. A hard interruption can leave a historical `running` row; the OS lock releases automatically and the next run can reconcile unfinished work. Preserve failed runs for diagnosis. `--no-llm` is an explicit deterministic fallback, not an LLM success.

## Backup and recovery

Back up `.env`, private state/reports, and stopped MISP/OpenCTI named volumes to private storage before upgrades. Logical database backup and a tested restore are required before treating the lab as durable. Never commit secrets or private backups. Restore the matching secret material with encrypted data; do not generate a replacement `.env` over an existing deployment. To pause only daily automation, disable `ti-brief.timer`; to free memory, stop the owned Compose services. No cleanup script deletes volumes or unrelated images.

Upgrade intentionally: review upstream release notes, refresh `scripts/lock_images.py` selectors, resolve images, regenerate Compose, run CI, and pilot against backed-up lab data. Never replace a healthy image merely because a mutable upstream tag moved.
