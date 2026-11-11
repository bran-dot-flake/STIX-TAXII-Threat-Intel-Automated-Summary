#!/usr/bin/env python3
"""Create lab secrets once, exclusively, with restrictive Unix permissions."""
import os
import base64
import secrets
import uuid
from pathlib import Path


def initialize(path=Path(".env")):
    content = Path(".env.example").read_text(encoding="utf-8")
    replacements = {}
    for line in content.splitlines():
        if "=CHANGE_" in line:
            key, marker = line.split("=", 1)
            if key.endswith(("TOKEN", "CONNECTOR_ID")):
                replacements[marker] = str(uuid.uuid4())
            elif key == "OPENCTI_ENCRYPTION_KEY":
                replacements[marker] = base64.b64encode(secrets.token_bytes(32)).decode()
            else:
                replacements[marker] = secrets.token_hex(20 if key == "ADMIN_KEY" else 32)
    for marker, value in replacements.items():
        content = content.replace(marker, value)
    # Initial API credentials align across the stack. Use dedicated users later.
    values = dict(line.split("=", 1) for line in content.splitlines() if line and not line.startswith("#"))
    content = content.replace("MISP_API_KEY=", "MISP_API_KEY=" + values["ADMIN_KEY"], 1)
    content = content.replace("OPENCTI_TOKEN=", "OPENCTI_TOKEN=" + values["OPENCTI_ADMIN_TOKEN"], 1)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    print("Created .env without printing secrets. Set OLLAMA_MODEL to an existing local model.")


if __name__ == "__main__":
    initialize()
