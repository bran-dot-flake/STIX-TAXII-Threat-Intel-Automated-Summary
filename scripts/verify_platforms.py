#!/usr/bin/env python3
"""Explicit live API acceptance, without printing credentials or source payloads."""
import argparse
import json
from pathlib import Path
from ti_brief.cli import load_env, required
from ti_brief.feeds import demo_records
from ti_brief.http import Http
from ti_brief.platforms import Misp, OpenCti


if __name__ == "__main__":
    import os
    parser = argparse.ArgumentParser()
    parser.add_argument("--misp", action="store_true")
    parser.add_argument("--opencti", action="store_true")
    parser.add_argument("--write-synthetic", action="store_true", help="Create/update one explicitly synthetic, private MISP event")
    args = parser.parse_args()
    load_env(Path(".env"))
    h = Http(timeout=90)
    result = {}
    if args.misp:
        misp = Misp(h, os.environ.get("MISP_URL", "http://127.0.0.1:8081"), required("MISP_API_KEY"))
        version = h.json(misp.url + "/servers/getVersion", headers=misp.headers)
        if not version.get("version"):
            raise SystemExit("MISP did not return its version")
        result["misp_version"] = version["version"]
        if args.write_synthetic:
            record = demo_records()[0]
            misp.sync(record)
            misp.sync(record)
            result["misp_synthetic_readback"] = misp.read(record)
    if args.opencti:
        cti = OpenCti(h, os.environ.get("OPENCTI_URL", "http://127.0.0.1:8080"), required("OPENCTI_TOKEN"))
        me = h.json(cti.url + "/graphql", {"query": "{ me { id } }"}, cti.headers)
        if me.get("errors") or not me.get("data", {}).get("me", {}).get("id"):
            raise SystemExit("OpenCTI authenticated health query failed")
        result["opencti_authenticated"] = True
        result["opencti_synthetic_context"] = cti.context(demo_records()[0])
    print(json.dumps(result))
