"""Versioned original editorial vectors, bound to approved weekly lead wording.

Artwork is an optional cached publication artifact. No browser/model-generated
markup is trusted. Unknown subjects are omitted, not given generic imagery.
"""

import copy
import hashlib
import math
import re
import xml.etree.ElementTree as ET
from .editorial import digest

NS = "http://www.w3.org/2000/svg"
CREAM = "#e9e7dd"
ORANGE = "#ee9468"
FIELDS = {"version", "edition_id", "lead_digest", "kind", "alt", "svg", "digest"}
ALTS = {
    "llm": "Conceptual illustration of cloud AI, an access key and rising costs.",
    "ransomware": "Conceptual illustration of files behind a lock.",
    "phishing": "Conceptual illustration of a message and a credential hook.",
    "exploitation": "Conceptual illustration of an exposed system and a security weakness.",
    "botnet": "Conceptual illustration of linked compromised devices.",
}


def lead_digest(edition):
    return digest(
        {
            "headline": edition.get("headline") or edition["topics"][0]["headline"],
            "lead": edition["plan"]["overview"][0],
            "evidence": (
                edition["evidence_digest"]
                if edition.get("version") == 3
                else edition["input_digest"]
            ),
        }
    )


def subject(edition):
    candidates = [
        edition.get("headline") or edition["topics"][0]["headline"],
        edition["plan"]["overview"][0][0]["text"],
    ]
    for text in candidates:
        for kind, pattern in (
            (
                "llm",
                r"llmjacking|llm hijack|language.model.*hijack|hijack.*language.model",
            ),
            ("ransomware", r"ransomware"),
            ("phishing", r"phishing"),
            ("botnet", r"botnet"),
            ("exploitation", r"exploit|authentication bypass|remote code execution"),
        ):
            if re.search(pattern, text, re.I):
                return kind
    return None


def render(kind):
    """Style version 1; preserve these compositions for historical validation."""

    def path(d, color=CREAM):
        return f'<path d="{d}" stroke="{color}"/>'

    def rect(x, y, w, h):
        return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9"/>'

    if kind == "llm":
        shapes = [
            path(
                "M 125 300 C 50 300 45 195 110 175 C 110 110 175 90 220 120 C 275 25 420 60 425 170 C 510 180 505 300 430 300"
            ),
            rect(225, 170, 88, 80),
        ]
        for x in (240, 269, 298):
            shapes += [path(f"M {x} 154 V 170 M {x} 250 V 267")]
        for y in (185, 210, 235):
            shapes += [path(f"M 209 {y} H 225 M 313 {y} H 329")]
        shapes += [
            path(
                "M 269 187 L 277 203 L 293 210 L 277 218 L 269 234 L 261 218 L 245 210 L 261 203 Z"
            ),
            '<circle cx="119" cy="300" r="22" stroke="' + ORANGE + '"/>',
            path("M 141 300 H 205 M 173 300 V 314 M 192 300 V 322", ORANGE),
            path(
                "M 360 315 L 418 260 L 465 277 L 550 112 M 514 124 L 550 112 L 560 151",
                ORANGE,
            ),
        ]
    elif kind == "ransomware":
        shapes = [
            rect(150, 90, 145, 220),
            path("M 175 135 H 260 M 175 165 H 250 M 175 195 H 240"),
            rect(280, 195, 140, 105),
            path("M 310 195 V 167 C 310 111 390 111 390 167 V 195", ORANGE),
            '<circle cx="350" cy="239" r="8" stroke="' + ORANGE + '"/>',
            path("M 350 247 V 268", ORANGE),
        ]
    elif kind == "phishing":
        shapes = [
            rect(120, 140, 260, 165),
            path(
                "M 125 150 L 250 238 L 375 150 M 125 295 L 210 220 M 375 295 L 290 220"
            ),
            path(
                "M 480 75 V 245 C 480 312 400 312 400 255 V 235 L 380 258 M 400 235 L 418 258",
                ORANGE,
            ),
        ]
    elif kind == "exploitation":
        shapes = [
            rect(155, 90, 300, 215),
            path("M 195 330 H 415 M 305 305 V 330 M 170 270 H 440"),
            path("M 320 125 L 285 185 L 320 195 L 290 246", ORANGE),
            '<circle cx="465" cy="120" r="38" stroke="' + ORANGE + '"/>',
            path("M 465 99 V 124 M 465 138 V 140", ORANGE),
        ]
    elif kind == "botnet":
        shapes = [
            path(
                "M 320 200 L 170 100 M 320 200 L 470 100 M 320 200 L 170 300 M 320 200 L 470 300",
                ORANGE,
            )
        ]
        for x, y in ((120, 65), (420, 65), (120, 265), (420, 265)):
            shapes += [
                rect(x, y, 100, 70),
                path(f"M {x+50} {y+70} V {y+86} M {x+25} {y+86} H {x+75}"),
            ]
        shapes += [
            '<circle cx="320" cy="200" r="38" stroke="' + ORANGE + '"/>',
            path("M 302 200 H 338 M 320 182 V 218", ORANGE),
        ]
    else:
        raise ValueError("Unknown artwork subject")
    svg = (
        '<svg xmlns="'
        + NS
        + '" viewBox="0 0 640 400" fill="none" stroke="'
        + CREAM
        + '" stroke-width="5" stroke-linecap="round" stroke-linejoin="round">'
        + "".join(shapes)
        + "</svg>"
    )
    return sanitize(svg)


def sanitize(svg):
    if (
        not isinstance(svg, str)
        or len(svg.encode()) > 12000
        or re.search(r"[&]|<\?|<!", svg)
    ):
        raise ValueError("Unsafe or oversized SVG")
    try:
        root = ET.fromstring(svg)
    except ET.ParseError:
        raise ValueError("Invalid SVG") from None
    if root.tag != "{" + NS + "}svg" or root.attrib.get("viewBox") != "0 0 640 400":
        raise ValueError("Invalid illustration viewport")
    allowed = {
        "svg",
        "g",
        "path",
        "rect",
        "circle",
        "ellipse",
        "line",
        "polyline",
        "polygon",
    }
    common = {"fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin"}
    attrs = {
        "svg": {"viewBox"},
        "g": set(),
        "path": {"d"},
        "rect": {"x", "y", "width", "height", "rx", "ry"},
        "circle": {"cx", "cy", "r"},
        "ellipse": {"cx", "cy", "rx", "ry"},
        "line": {"x1", "y1", "x2", "y2"},
        "polyline": {"points"},
        "polygon": {"points"},
    }
    nodes = list(root.iter())
    if len(nodes) > 64:
        raise ValueError("Illustration too complex")
    for node in nodes:
        tag = node.tag.removeprefix("{" + NS + "}")
        if (
            tag not in allowed
            or node.tag != "{" + NS + "}" + tag
            or (node is not root and tag == "svg")
        ):
            raise ValueError("Unsafe SVG element")
        if (node.text or "").strip() or (node.tail or "").strip():
            raise ValueError("Illustration contains text")
        for key, value in node.attrib.items():
            if key not in attrs[tag] | common:
                raise ValueError("Unsafe SVG attribute")
            if key in {"fill", "stroke"}:
                if value not in {CREAM, ORANGE, "none", "#141413"}:
                    raise ValueError("Unsafe SVG paint")
            elif key in {"stroke-linecap", "stroke-linejoin"}:
                if value not in {"round", "butt", "square", "miter", "bevel"}:
                    raise ValueError("Invalid line style")
            elif key in {"d", "points"}:
                if len(value) > 2000 or not re.fullmatch(
                    r"[MmLlHhVvCcSsQqTtAaZz0-9eE.,+\s-]+", value
                ):
                    raise ValueError("Invalid geometry")
                numbers = re.findall(r"[-+]?(?:\d*\.)?\d+(?:[eE][-+]?\d+)?", value)
                if len(numbers) > 500 or any(
                    not math.isfinite(float(n)) or abs(float(n)) > 4096 for n in numbers
                ):
                    raise ValueError("Unbounded geometry")
            else:
                numbers = value.split() if key == "viewBox" else [value]
                if any(
                    not math.isfinite(float(n)) or abs(float(n)) > 4096 for n in numbers
                ):
                    raise ValueError("Unbounded SVG value")
                if key == "stroke-width" and not 2 <= float(value) <= 8:
                    raise ValueError("Invalid stroke width")
    ET.register_namespace("", NS)
    return ET.tostring(root, encoding="unicode", short_empty_elements=True)


def make(edition):
    kind = subject(edition)
    if kind is None:
        return None
    svg = sanitize(render(kind))
    return {
        "version": 1,
        "edition_id": edition["id"],
        "lead_digest": lead_digest(edition),
        "kind": kind,
        "alt": ALTS[kind],
        "svg": svg,
        "digest": hashlib.sha256(svg.encode()).hexdigest(),
    }


def asset_path(art):
    return "assets/briefs/" + art["edition_id"] + "-" + art["digest"][:16] + ".svg"


def validate(snapshot):
    from .publication import exact_fields, valid_id, clean_text

    arts = snapshot["illustrations"]
    if not isinstance(arts, list) or len(arts) > 90:
        raise ValueError("Invalid illustration history")
    editions = {
        e["id"]: e
        for e in snapshot["editions"]
        if e.get("publication_kind") == "weekly" and e["topics"]
    }
    seen = set()
    for art in arts:
        exact_fields(art, FIELDS)
        valid_id(art["edition_id"])
        clean_text(art["alt"], 240)
        for field in ("lead_digest", "digest"):
            if not isinstance(art[field], str) or not re.fullmatch(
                "[0-9a-f]{64}", art[field]
            ):
                raise ValueError("Invalid artwork digest")
        if (
            not isinstance(art["kind"], str)
            or art["kind"] not in ALTS
            or type(art["version"]) is not int
        ):
            raise ValueError("Invalid artwork type")
        if (
            art["edition_id"] not in editions
            or art["edition_id"] in seen
            or art["version"] != 1
        ):
            raise ValueError("Invalid illustration association")
        sanitize(art["svg"])
        if art != make(editions[art["edition_id"]]):
            raise ValueError("Illustration differs from approved lead")
        seen.add(art["edition_id"])
    return arts


def enrich(snapshot):
    existing = {a["edition_id"]: a for a in snapshot.get("illustrations", [])}
    result = []
    for edition in snapshot.get("editions", []):
        if edition.get("publication_kind") != "weekly" or not edition["topics"]:
            continue
        old = existing.get(edition["id"])
        if old and old["lead_digest"] == lead_digest(edition):
            result.append(copy.deepcopy(old))
            continue
        try:
            art = make(edition)
            if art:
                result.append(art)
        except (ValueError, TypeError, KeyError):
            # Optional artwork failure must never withhold an accepted briefing.
            continue
    snapshot["illustrations"] = result
    snapshot["schema_version"] = 7
    return snapshot
