#!/usr/bin/env python3
"""Check tracked documentation links, SVG safety and private-path exclusions."""

import html
import json
import re
import subprocess
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def anchors(text):
    used = {}
    result = set(re.findall(r'\bid=["\']([^"\']+)', text))
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    for heading in re.findall(r"^#{1,6}\s+(.+)$", text, re.M):
        label = re.sub(r"<[^>]+>|[`*_]", "", heading).lower()
        label = "".join(c for c in label if c in " -_" or unicodedata.category(c)[0] in "LN")
        slug = label.replace(" ", "-")
        count = used.get(slug, 0)
        used[slug] = count + 1
        result.add(slug + (f"-{count}" if count else ""))
    return result


def check():
    names = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    files = [ROOT / name for name in names if (ROOT / name).is_file()]
    for name in names:
        if (
            name == ".env"
            or name.startswith(("data/", "reports/", "assessments/", "work/", ".venv/"))
            or name.endswith((".pem", ".key", ".sqlite3"))
        ):
            raise ValueError(f"Private/runtime path is tracked: {name}")
    count = 0
    documents = [p for p in files if p.suffix == ".md"]
    for path in documents:
        text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)
        targets = re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", text)
        targets += re.findall(r'(?:href|src)=["\']([^"\']+)', text, re.I)
        for target in targets:
            parsed = urlsplit(html.unescape(target).strip("<>"))
            if parsed.scheme or parsed.netloc:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            destination.relative_to(ROOT)
            if not destination.exists():
                raise ValueError(f"Broken relative link in {path.relative_to(ROOT)}: {target}")
            # Match GitHub's case-sensitive paths even on a Windows checkout.
            current = ROOT
            for part in destination.relative_to(ROOT).parts:
                if part not in {p.name for p in current.iterdir()}:
                    raise ValueError(f"Incorrect path case: {target}")
                current /= part
            if parsed.fragment and destination.suffix == ".md":
                if unquote(parsed.fragment) not in anchors(destination.read_text(encoding="utf-8")):
                    raise ValueError(f"Broken section link in {path.relative_to(ROOT)}: {target}")
            count += 1
    svgs = [p for p in files if p.suffix == ".svg"]
    for path in svgs:
        source = path.read_text(encoding="utf-8")
        if "<!DOCTYPE" in source.upper() or "<!ENTITY" in source.upper():
            raise ValueError(f"Unsupported SVG declaration: {path.relative_to(ROOT)}")
        root = ET.fromstring(source)
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] in {"script", "foreignObject"}:
                raise ValueError(f"Active SVG content: {path.relative_to(ROOT)}")
            for key, value in element.attrib.items():
                if key.lower().startswith("on") or (
                    key.endswith("href") and not value.startswith("#")
                ):
                    raise ValueError(f"External/active SVG attribute: {path.relative_to(ROOT)}")
        if path.name == "architecture.svg":
            _, _, width, height = map(float, root.attrib["viewBox"].split())
            if width < 3 * height:
                raise ValueError("Architecture diagram is not compact and horizontal")
    return {
        "status": "passed",
        "documents": len(documents),
        "local_links": count,
        "svg_files": len(svgs),
    }


if __name__ == "__main__":
    print(json.dumps(check()))
