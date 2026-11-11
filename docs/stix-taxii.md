# STIX 2.1 / TAXII 2.1 operations

EMBER uses the OASIS `stix2` parser and `taxii2-client.v21` endpoint/filter models. The initial live source is [MITRE's public TAXII service](https://attack.mitre.org/resources/attack-data-and-tools/), discovery `https://attack-taxii.mitre.org/taxii2/`, API root `/api/v21/`, Enterprise collection `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019`.

This is a knowledge-base integration. Publication/modification dates do not represent new attacks or local detection. The initial import is deliberately bounded and incomplete.

## Installation and commands

No system package, extra container, or daemon is required. Create a project-owned environment:

```sh
python3 -m venv work/stix-venv
work/stix-venv/bin/python3 -m pip install -r requirements-stix.lock
export PYTHONPATH=src
work/stix-venv/bin/python3 scripts/sync_taxii.py --discover
work/stix-venv/bin/python3 scripts/sync_taxii.py --sync
work/stix-venv/bin/python3 scripts/sync_taxii.py \
  --bundle tests/fixtures/mitre-taxii.sample.json --source example
```

`--discover` lists available collection IDs/titles without pulling objects. `--sync` selects the configured readable collection and commits bounded pages. Local bundles use the same STIX parser and a separate `bundle-<source>` namespace. They cannot claim the trusted MITRE publication namespace. The default database is ignored private state at `data/stix/intelligence.sqlite3`.

For another HTTPS TAXII service:

```sh
work/stix-venv/bin/python3 scripts/sync_taxii.py --discover \
  --discovery https://taxii.example.org/taxii2/ --source private-feed
work/stix-venv/bin/python3 scripts/sync_taxii.py --sync \
  --discovery https://taxii.example.org/taxii2/ --root https://taxii.example.org/root/ \
  --collection COLLECTION_ID --source private-feed --types indicator,malware,report,ipv4-addr
```

The example hostname is a placeholder. Supply credentials privately through `TAXII_USER` plus `TAXII_PASSWORD`, or `TAXII_TOKEN` for bearer auth. Do not use both modes or embed credentials in a URL. MITRE's public origin never receives those optional private-feed credentials. TLS verification is mandatory; redirects and cross-origin API roots are rejected rather than forwarding authentication. Legitimate cross-host deployments need an explicitly separate configured discovery endpoint. These private sources are never automatically published.

## Storage, versions, and relationships

Known STIX 2.1 SDOs and SCOs are validated by `stix2`. Required source IDs/spec versions/timestamps are checked before parsing so missing values are not silently filled by constructor defaults. Custom STIX extensions are retained; custom object types remain opaque rather than acquiring invented standard semantics. Pages/bundles are size-bounded and fully parsed before database mutation.

Original JSON is retained per source/ID/version. SDO version keys normalize `modified` to UTC microseconds. Repeated payloads deduplicate; a changed payload with the same ID/version fails instead of replacing history. Immutable marking definitions also reject conflicting payloads. Unversioned SCO variants use content hashes; their current view selects the latest inserted variant and supplies no artificial modification timestamp.

Relationships retain their original STIX IDs, types, source/target references, timestamps, markings, and source namespace. Reports keep their `object_refs`; identities and marking definitions stay in the same store. Dangling references remain stored, not asserted as resolved. A bounded dependency pass fetches missing relationship endpoints and marking definitions. No IOC URL is dereferenced.

`latest(active_only=True)` excludes revoked and MITRE-deprecated objects. Historical versions remain. Public relationships require both eligible active endpoints. The LLM cannot create edges. Public projection currently supports named MITRE techniques, groups, malware, and tools with exact ATT&CK external IDs/URLs; other parsed STIX types remain local until an appropriate publication policy exists.

## Pagination and incremental checkpoints

Three independently checkpointed streams cover definitions, entities/observables, and relationships. Definitions are checked first. Defaults are 100 objects/page, two pages per main stream, one definition page, and twelve dependency requests. Bounds are configurable through `--page-size`, `--max-pages`, and `--resolve`; `--types` changes the entity stream. Repeated runs continue the initial traversal without downloading it all each day. Catalog readers iterate stored payloads rather than loading every raw object at once.

Every accepted page and its continuation token commit in one SQLite transaction. A failed parse/write leaves that page unacknowledged. The incremental `added_after` watermark advances only after `more=false`, using validated TAXII date-added response headers, not a local clock or object modification dates. A one-second overlap preserves equal-timestamp updates; version deduplication absorbs repeats. Empty incrementals leave the safe watermark intact.

Continuation tokens are opaque and stored with the page size/type filter and discovered-release fingerprint. Changing those parameters restarts bounded traversal. An expired continuation (HTTP 400/404) clears the pending token while retaining the previous completed watermark, then defers for safe replay. Repeated/missing tokens and empty continuation pages fail closed.

The current MITRE service can return old date-added timestamps for recently modified objects. Changes to its discovered API-root/release set trigger bounded replay, protecting against relying solely on those timestamps for a new release. This is not a guarantee against undocumented in-place upstream changes without a release/root change; a deliberate database/source reset can replay after investigation. Preserve the prior state as evidence rather than deleting it blindly.

## Transport and resource limits

The library uses a GET-only connection adapter with TLS, origin pinning, no redirects, 25-second connection/read bounds, an eight-MB response bound, a one-MB per-object bound, and at most three attempts per request. JSON MIME parameters are parsed, including quoted TAXII version values. Source body/URL/auth details are excluded from exceptions.

HTTP 429 and transient 5xx responses honor numeric/date `Retry-After`. Waits above 45 seconds defer to a later run rather than blocking the scheduler. A persistent SQLite budget caps this project's origin requests at 35 per ten minutes, beneath [MITRE's published 50-request limit](https://raw.githubusercontent.com/mitre-attack/attack-workbench-taxii-server/main/docs/USAGE.md). Other clients behind the same IP can still cause a server-side limit. Successfully committed pages survive timeout, rate deferral, and process interruption.

Dependencies are optional and pinned in `requirements-stix.lock`. The Pages build uses only standard-library projection validation; it does not install STIX libraries or contact TAXII. No browser tools are installed on the VM.

## Optional OpenCTI catalog bridge

```sh
PYTHONPATH=src python3 scripts/sync_stix_opencti.py --max-objects 20
```

This uses the existing private `OPENCTI_URL` / `OPENCTI_TOKEN`. It imports approved active MITRE attack patterns, intrusion sets, malware, tools, and resolved source relationships through native add/upsert APIs. Source STIX IDs and external references are preserved. Exact source identity/name and relationship type/endpoints are read back before recording a successful version checkpoint. An unchanged checkpoint prevents duplicate writes; failed read-back leaves work pending. Endpoint writes precede relationship writes.

MISP remains the existing IOC/event writer. The bridge is not a generic STIX import replacement: raw report/SCO metadata, revoked/deprecated history, unhandled custom types, and private bundle imports remain in the local store. Previously imported inactive OpenCTI catalog entries are not automatically retired by this narrow bridge; review them or use OpenCTI's fuller lifecycle importer when that behavior is needed. Public projection independently removes inactive objects and their edges.

## Daily operation and failure behavior

Set `TI_TAXII_ENABLED=true` and `TI_STIX_PYTHON=work/stix-venv/bin/python3` in the existing private environment. The approved daily job performs bounded TAXII collection before its unchanged platform/reporting stages. `TI_STIX_OPENCTI_ENABLED=true` optionally runs the bridge after platform restoration; OpenCTI must be available (for example, the measured `all` resident profile). No systemd change is necessary.

TAXII/bridge failures log a redacted stage/error class and do not suppress publication of previously valid data. A source is marked syncing before requests; only a completed bounded run becomes publishable. Failed or interrupted imports retain the last accepted public context, rather than exposing partial changes before markings are checked. Missing dependency endpoints remain unresolved and are not asserted. A core reporting failure still follows its original exit path. The public exporter runs from the existing finally hook, preserving independent collection/publication when integrations fail.

Only the exact original MITRE discovery/root/Enterprise collection qualifies for public STIX projection. Explicit permissive TLP or the reviewed MITRE copyright marking is required; unknown/restricted/granular markings fail closed. The reviewed copyright statement is intentionally exact: a changed marking/license requires review. Private namespaces, local bundles, auth, raw payloads, and OpenCTI IDs never enter public JSON. [MITRE terms](https://attack.mitre.org/resources/terms-of-use/).

## Verification

The checked-in `tests/fixtures/mitre-taxii.sample.json` is a minimized, real November 11 TAXII sample: one original relationship, its two endpoints, and the original copyright marking. IDs, versions, and relationship direction are retained; descriptions/unneeded properties were omitted. Synthetic STIX objects in tests cover additional SDOs, SCOs, reports, and restrictions without pretending MITRE supplies daily IOC telemetry.

```sh
PYTHONPATH=src work/stix-venv/bin/python3 -m unittest discover -s tests -v
node --test tests/dashboard.test.mjs
PYTHONPATH=src work/stix-venv/bin/python3 scripts/sync_taxii.py --sync --max-pages 1 --page-size 50
```

Live acceptance verified discovery, API-root/collection listing, bounded page retrieval, subsequent page resume, an incremental definitions stream, parsing/storage, and marking-gated projection. The local store reached 220 original objects; the public projection contained 61 nodes and five resolved edges. A real three-object OpenCTI import repeated with zero extra writes. Browser acceptance checks search, charts, CVEs, archive, catalog details, and relationships at 390/768/1440 widths. Additional private sources, full catalog coverage, and broader platform lifecycle import remain separate work.
