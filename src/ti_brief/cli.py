import argparse
import json
import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from .feeds import collect, demo_records
from .http import Http
from .platforms import Misp, OpenCti
from .report import atomic_write, evidence_digest, llm_select, render
from .store import Store


def load_env(path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip().replace("_", "").isalnum():
            raise ValueError("Invalid environment file")
        os.environ.setdefault(key.strip(), value.strip())


@contextmanager
def run_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            if path.stat().st_size == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise RuntimeError("Another pipeline run holds the lock") from None
        else:
            import fcntl
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RuntimeError("Another pipeline run holds the lock") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def required(name):
    value = os.environ.get(name, "")
    if not value or "CHANGE" in value.upper():
        raise ValueError(f"Configure {name} before running live integration")
    return value


def resource_observation():
    if not Path("/proc/meminfo").exists():
        return {"available": False}
    mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    return {"guest_mem_available_mib": int(mem["MemAvailable"].split()[0]) // 1024,
            "guest_swap_used_mib": (int(mem["SwapTotal"].split()[0]) - int(mem["SwapFree"].split()[0])) // 1024,
            "load_1_5_15": os.getloadavg()}


def synchronize_misp(store, misp, limit):
    pending = store.pending("misp_version", limit)
    for record in pending:
        uid = misp.sync(record)
        misp.read(record)
        store.checkpoint(record, "misp_version", uid)
    return len(pending)


def execute(args):
    if not args.demo:
        load_env(args.env)
    mode = "demo" if args.demo else "live"
    root = args.data_dir / mode
    with run_lock(root / "run.lock"):
        store = Store(root / "state.sqlite3")
        run_id, started = store.start_run(), time.monotonic()
        details = {"mode": mode, "collect_only": args.collect_only, "resources_at_start": resource_observation()}
        try:
            http = Http()
            records = [] if args.render_prepared else demo_records() if args.demo else collect(http, args.feeds.split(","), args.lookback_days)
            details["collected"] = len(records)
            details["changed"] = store.upsert(records)
            if args.collect_only:
                details["elapsed_seconds"] = round(time.monotonic() - started, 2)
                details["resources_at_end"] = resource_observation()
                store.finish_run(run_id, "collected", details)
                print(json.dumps(details))
                return 0
            if args.sync_misp_only:
                misp = Misp(http, os.environ.get("MISP_URL", "http://127.0.0.1:8081"), required("MISP_API_KEY"))
                details.update(status="misp-synchronized", synchronized=synchronize_misp(store, misp, args.max_sync),
                    elapsed_seconds=round(time.monotonic() - started, 2), resources_at_end=resource_observation())
                store.finish_run(run_id, "misp-synchronized", details)
                print(json.dumps(details))
                return 0
            selected = store.pending("reported_version", args.max_records)
            contexts = {}
            prepared_path = root / "prepared.json"
            if args.render_prepared:
                prepared = json.loads(prepared_path.read_text())
                age = datetime.now(timezone.utc) - datetime.fromisoformat(prepared["prepared_at"])
                if not 0 <= age.total_seconds() <= 86400:
                    raise ValueError("Prepared evidence has expired")
                if prepared["records"] != [{"id": r.key, "version": r.version} for r in selected]:
                    raise ValueError("Prepared evidence changed; prepare a new snapshot")
                contexts = prepared["platform_context"]
            if not args.demo and not args.render_prepared:
                misp = Misp(http, os.environ.get("MISP_URL", "http://127.0.0.1:8081"), required("MISP_API_KEY"))
                opencti = OpenCti(http, os.environ.get("OPENCTI_URL", "http://127.0.0.1:8080"), required("OPENCTI_TOKEN"))
                synchronize_misp(store, misp, args.max_sync)
                bridged = 0
                for record in store.pending("opencti_version", args.max_sync):
                    if record.kind == "vulnerability":
                        misp.read(record)
                        opencti.sync_vulnerability(record, os.environ.get("BASE_URL", "http://localhost:8081"))
                        store.checkpoint(record, "opencti_version")
                        bridged += 1
                details["cves_bridged"] = bridged
                sync_deadline = time.monotonic() + args.sync_timeout
                for record in selected:
                    misp_context = misp.read(record)
                    deadline = sync_deadline
                    requeued = False
                    while True:
                        cti_context = opencti.context(record)
                        if not args.sync_timeout or cti_context["verified_sync_ids"]:
                            break
                        if record.kind != "vulnerability" and not requeued:
                            # Reconcile a timestamp-pagination miss with the same UUID.
                            misp.sync(record)
                            requeued = True
                        if time.monotonic() >= deadline:
                            raise RuntimeError("OpenCTI synchronization not verified within deadline")
                        time.sleep(min(10, max(0, deadline - time.monotonic())))
                    contexts[record.key] = {"misp": misp_context, "opencti": cti_context}
                # Fail even on quiet days if a configured platform is unavailable.
                if not selected:
                    http.json(os.environ.get("MISP_URL", "http://127.0.0.1:8081").rstrip("/") + "/servers/getVersion", headers=misp.headers)
                    result = http.json(opencti.url + "/graphql", {"query": "{ me { id } }"}, opencti.headers)
                    if result.get("errors") or not result.get("data", {}).get("me", {}).get("id"):
                        raise RuntimeError("OpenCTI health query failed")
            if args.prepare_only:
                atomic_write(prepared_path, json.dumps({"prepared_at": datetime.now(timezone.utc).isoformat(),
                    "records": [{"id": r.key, "version": r.version} for r in selected], "platform_context": contexts}, indent=2))
                details.update(status="prepared", records=len(selected), elapsed_seconds=round(time.monotonic() - started, 2))
                details["resources_at_end"] = resource_observation()
                store.finish_run(run_id, "prepared", details)
                print(json.dumps(details))
                return 0
            status, report_mode = "complete", "deterministic evidence report"
            selection = [{"record_id": r.key, "excerpt": r.title[:400]} for r in selected]
            if not args.demo and not args.no_llm and selected:
                try:
                    selection = llm_select(Http(timeout=600, retries=0), os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"), required("OLLAMA_MODEL"), selected)
                    report_mode = "Ollama selected, validated source excerpts"
                except (RuntimeError, ValueError, KeyError, TypeError) as exc:
                    status, report_mode = "degraded", "DEGRADED: Ollama failed validation or inference; deterministic evidence fallback"
                    details["llm_error_type"] = type(exc).__name__
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
            output = args.reports_dir / mode / f"{stamp}-run-{run_id}.md"
            atomic_write(output, render(selected, selection, store, report_mode, contexts, args.demo))
            # Sidecar allows independent verification and never includes API credentials.
            atomic_write(output.with_suffix(".json"), json.dumps({"run_id": run_id, "status": status,
                "evidence_digest": evidence_digest(selected), "records": [{"id": r.key, "version": r.version} for r in selected],
                "selection": selection, "platform_context": contexts}, indent=2))
            # Failed LLM runs keep records pending so the next run retries the brief.
            if status == "complete":
                for r in selected:
                    store.checkpoint(r, "reported_version")
            details.update(report=str(output), status=status, reported=len(selected),
                           remaining=store.pending_count("reported_version"),
                           elapsed_seconds=round(time.monotonic() - started, 2))
            details["resources_at_end"] = resource_observation()
            store.finish_run(run_id, status, details)
            print(json.dumps(details))
            return 0 if status == "complete" else 2
        except Exception as exc:
            # Record type only: third-party errors can contain secrets or hostile data.
            details.update(error_type=type(exc).__name__, elapsed_seconds=round(time.monotonic() - started, 2))
            details["resources_at_end"] = resource_observation()
            store.finish_run(run_id, "failed", details)
            print(json.dumps({"status": "failed", **details}), file=sys.stderr)
            return 1
        finally:
            store.close()


def main(argv=None):
    if os.name != "nt":
        os.umask(0o077)
    p = argparse.ArgumentParser(description="Bounded threat-intelligence ingestion and evidence briefs")
    p.add_argument("--demo", action="store_true", help="Offline synthetic fixtures; isolated state and reports")
    p.add_argument("--collect-only", action="store_true", help="Fetch and normalize feeds without platform writes or LLM")
    p.add_argument("--sync-misp-only", action="store_true", help="Collect and synchronize MISP without OpenCTI or inference")
    p.add_argument("--no-llm", action="store_true", help="Explicitly select deterministic reporting")
    stages = p.add_mutually_exclusive_group()
    stages.add_argument("--prepare-only", action="store_true", help="Fetch, synchronize, and save platform context; defer inference")
    stages.add_argument("--render-prepared", action="store_true", help="Render a validated <24h snapshot without contacting platforms or feeds")
    p.add_argument("--env", type=Path, default=Path(".env"))
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    p.add_argument("--reports-dir", type=Path, default=Path("reports"))
    p.add_argument("--feeds", default="cisa-kev,circl-osint")
    p.add_argument("--lookback-days", type=int, default=14)
    p.add_argument("--max-records", type=int, default=8)
    p.add_argument("--max-sync", type=int, default=50)
    p.add_argument("--sync-timeout", type=int, default=0, help="Total seconds to wait for verified OpenCTI provenance (0: draft context only)")
    args = p.parse_args(argv)
    if args.collect_only and (args.prepare_only or args.render_prepared):
        p.error("Collection-only cannot be combined with staged reporting")
    if args.sync_misp_only and (args.collect_only or args.prepare_only or args.render_prepared or args.demo):
        p.error("MISP-only synchronization is a separate live ingestion stage")
    if not 0 <= args.sync_timeout <= 900:
        p.error("Synchronization timeout must be 0..900 seconds")
    if not 1 <= args.max_records <= 8 or not args.max_records <= args.max_sync <= 500 or not 1 <= args.lookback_days <= 90:
        p.error("Require records 1..8, sync >= records and <=500, lookback 1..90")
    try:
        return execute(args)
    except (RuntimeError, ValueError) as exc:
        print(f"Cannot start pipeline: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
