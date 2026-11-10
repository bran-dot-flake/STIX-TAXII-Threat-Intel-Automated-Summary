#!/usr/bin/env python3
"""Live feed + real local inference smoke test; no platform success is implied."""
import json
import os
import time
from pathlib import Path
from ti_brief.feeds import collect
from ti_brief.http import Http
from ti_brief.report import atomic_write, llm_select, render
from ti_brief.store import Store


if __name__ == "__main__":
    started = time.monotonic()
    # A distinct smoke namespace cannot acknowledge production pipeline records.
    records = sorted(collect(Http(), ["cisa-kev"], 14), key=lambda r: (r.published_at or "", r.key), reverse=True)[:3]
    if not records:
        raise SystemExit("No recent KEV records for inference smoke test")
    selection = llm_select(Http(timeout=600, retries=0), "http://127.0.0.1:11434", os.environ.get("OLLAMA_MODEL", "llama3.2:latest"), records)
    store = Store(Path("data/smoke/state.sqlite3"))
    try:
        store.upsert(records)
        mode = "SMOKE TEST: real feed and real Ollama; MISP/OpenCTI not connected"
        atomic_write(Path("reports/smoke/live-ollama-smoke.md"), render(records, selection, store, mode, {}))
        result = {"records": len(records), "validated_excerpts": len(selection), "elapsed_seconds": round(time.monotonic() - started, 2),
                  "model": os.environ.get("OLLAMA_MODEL", "llama3.2:latest"), "platforms_tested": False}
        atomic_write(Path("reports/smoke/result.json"), json.dumps(result, indent=2))
        print(json.dumps(result))
    finally:
        store.close()
