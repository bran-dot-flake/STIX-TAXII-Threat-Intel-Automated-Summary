"""Publish exactly one validated JSON file through existing gh authentication.

No working-tree upload, git credential export, force push, or stored token.
"""
import json
import re
import subprocess
from .publication import validate_snapshot

DEFAULT_REPOSITORY = "bran-dot-flake/STIX-TAXII-Threat-Intel-Automated-Summary"
DATA_BRANCH = "intel-data"


def gh_api(endpoint, payload=None, method=None):
    command = ["gh", "api", endpoint]
    if method:
        command += ["--method", method]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
        text=True, capture_output=True, timeout=60)
    if result.returncode:
        # Do not expose gh's response body, configuration, or credentials.
        raise RuntimeError("GitHub API request failed")
    return json.loads(result.stdout) if result.stdout.strip() else None


def data_head(repo, api=gh_api):
    # A branch-list read distinguishes a missing branch from an auth/network error.
    branches = api(f"repos/{repo}/branches?per_page=100")
    if len(branches) == 100:
        raise ValueError("Too many branches for bounded publisher")
    match = next((b for b in branches if b["name"] == DATA_BRANCH), None)
    return match["commit"]["sha"] if match else None


def read_remote(repo, api=gh_api):
    if not data_head(repo, api):
        return None
    import base64
    content = api(f"repos/{repo}/contents/snapshot.json?ref={DATA_BRANCH}")
    if content["encoding"] != "base64" or content["size"] > 8_000_000:
        raise ValueError("Unexpected remote publication")
    return validate_snapshot(json.loads(base64.b64decode(content["content"], validate=False)))


def publish(snapshot, repo=DEFAULT_REPOSITORY, api=gh_api):
    validate_snapshot(snapshot)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Invalid repository")
    if not snapshot["records"] and not snapshot["news"]:
        raise ValueError("Refusing an empty live publication")
    head = data_head(repo, api)
    if head:
        commit = api(f"repos/{repo}/git/commits/{head}")
        tree = api(f"repos/{repo}/git/trees/{commit['tree']['sha']}")
        if tree.get("truncated") or {n["path"] for n in tree["tree"]} != {"snapshot.json"}:
            raise ValueError("Publication branch contains unexpected files")
    # Build a new, explicitly allowlisted tree. No local path is ever staged.
    tree = api(f"repos/{repo}/git/trees", {"tree": [{"path": "snapshot.json", "mode": "100644", "type": "blob",
        "content": json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"}]})
    commit = api(f"repos/{repo}/git/commits", {"message": "Publish public-source intelligence snapshot", "tree": tree["sha"],
        "parents": [head] if head else []})
    if head:
        # An intervening sibling commit fails fast-forward; never force or retry blindly.
        api(f"repos/{repo}/git/refs/heads/{DATA_BRANCH}", {"sha": commit["sha"], "force": False}, "PATCH")
    else:
        api(f"repos/{repo}/git/refs", {"ref": "refs/heads/" + DATA_BRANCH, "sha": commit["sha"]})
    try:
        api(f"repos/{repo}/actions/workflows/pages.yml/dispatches", {"ref": "main"})
    except RuntimeError:
        # The immutable public data commit succeeded. Hosting quota/dispatch
        # failures must not make an accepted edition appear unpublished locally.
        print(json.dumps({'stage':'pages','status':'dispatch-failed-data-committed','commit':commit['sha']}))
    return commit["sha"]
