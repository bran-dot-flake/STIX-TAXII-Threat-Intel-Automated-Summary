#!/usr/bin/env python3
"""Resolve public upstream image tags to immutable OCI manifest digests.

Run intentionally when upgrading; review and commit the resulting lock file.
No Docker daemon, credentials or image layer downloads are needed.
"""
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TAGS = {
    "misp-core": "ghcr.io/misp/misp-docker/misp-core:v2.5.51",
    "misp-nginx": "ghcr.io/misp/misp-docker/misp-nginx:v2.5.51",
    "misp-modules": "ghcr.io/misp/misp-docker/misp-modules:v3.1.4",
    "misp-db": "mariadb:10.11.15",
    "misp-redis": "valkey/valkey:7.2.11",
    "opencti": "opencti/platform:7.261109.0",
    "worker": "opencti/worker:7.261109.0",
    "connector-misp": "opencti/connector-misp:7.261109.0",
    "elasticsearch": "docker.elastic.co/elasticsearch/elasticsearch:8.19.21",
    "redis": "redis:8.2.3",
    "rabbitmq": "rabbitmq:4.2.1-management",
    "minio": "pgsty/silo:RELEASE.2026-11-09T00-00-00Z",
}
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"))


def resolve(image):
    name, tag = image.rsplit(":", 1)
    first, _, rest = name.partition("/")
    registry = first if "." in first else "registry-1.docker.io"
    repository = rest if "." in first else name if "/" in name else "library/" + name
    url = f"https://{registry}/v2/{repository}/manifests/{tag}"
    headers = {"Accept": ACCEPT}
    try:
        response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30)
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        challenge = dict(re.findall(r'(\w+)="([^"]+)"', exc.headers["WWW-Authenticate"]))
        token_url = challenge.pop("realm") + "?" + urllib.parse.urlencode(challenge)
        with urllib.request.urlopen(token_url, timeout=30) as token_response:
            token = json.load(token_response)
        headers["Authorization"] = "Bearer " + (token.get("token") or token["access_token"])
        response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30)
    with response:
        digest = response.headers.get("Docker-Content-Digest")
        body = json.load(response)
        if not digest or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Registry did not return an OCI digest")
        manifests = body.get("manifests", [])
        if manifests and not any(m.get("platform", {}).get("architecture") == "amd64" and m.get("platform", {}).get("os") == "linux" for m in manifests):
            raise ValueError("Image has no Linux amd64 manifest")
        return {"tag": image, "image": name + "@" + digest, "digest": digest}


if __name__ == "__main__":
    images = {}
    for service, tag in TAGS.items():
        print(f"Resolving {service}: {tag}", flush=True)
        images[service] = resolve(tag)
    lock = {"resolved_at": datetime.now(timezone.utc).isoformat(), "platform": "linux/amd64", "images": images}
    Path("deploy/images.lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
