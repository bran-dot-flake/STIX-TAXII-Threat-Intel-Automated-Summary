#!/usr/bin/env python3
import json
import re
from pathlib import Path
from build_compose import build


def validate():
    config = json.loads(Path("deploy/compose.json").read_text())
    assert config == build(), "Compose is out of date; run scripts/build_compose.py"
    lock = json.loads(Path("deploy/images.lock.json").read_text())
    assert set(lock["images"]) == set(config["services"])
    for name, service in config["services"].items():
        assert re.search(r"@sha256:[0-9a-f]{64}$", service["image"]), name
        assert service["image"] == lock["images"][name]["image"]
        assert service["mem_limit"] == service["memswap_limit"]
        assert service["cpus"] > 0
        assert service["logging"]["options"]["max-file"] == "3"
        for port in service.get("ports", []):
            assert port.startswith("127.0.0.1:"), name
        for volume in service.get("volumes", []):
            assert "docker.sock" not in volume
    print(f"Validated {len(config['services'])} digest-pinned, resource-limited services and generated configuration")


if __name__ == "__main__":
    validate()
