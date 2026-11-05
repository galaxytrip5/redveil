# language: Python 3.11+, file: cf/techniques.py
# *clickfix technique catalog — surfaces, lolbins, telemetry, opsec notes*
from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from .stager import KINDS, Stager

SURFACES = ("winr", "terminal", "explorer", "protocol", "host", "share", "package", "persist")
CATEGORIES = ("clickfix", "lolbin", "protocol", "package", "share", "defense", "persist", "lateral")


@dataclass(frozen=True, slots=True)
class Technique:
    """One way to make a human run attacker content.

    kind      — stager kind this framework can serve end to end (None = needs
                operator infra: smb/webdav share, hosted msi/appx, file drop).
    template  — command template for kind=None entries; supports {url} {host}
                {token} {exe}. Never contains braces of its own.
    steps     — the exact victim instructions rendered on the lure page.
    telemetry — windows logging artifacts a blue team can expect.
    """

    id: str
    name: str
    surface: str
    category: str
    kind: str | None
    template: str
    steps: tuple[str, ...]
    clipboard: bool
    min_os: str
    mitre: str | None
    telemetry: tuple[str, ...]
    detection: str
    opsec: str
    reliability: int
    tags: tuple[str, ...] = field(default=())

    def command_for(self, base: str = "", token: str = "TOKEN") -> str:
        host = base.rstrip("/") if base else "https://HOST"
        if self.kind:
            return Stager.command(self.kind, f"{host}/s/{self.kind}/{token}")
        return self.template.format(url=host, host=host, token=token, exe="%TEMP%\\u.exe")

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "surface": self.surface,
            "category": self.category,
            "kind": self.kind,
            "serveable": self.kind is not None,
            "clipboard": self.clipboard,
            "min_os": self.min_os,
            "mitre": self.mitre,
            "telemetry": list(self.telemetry),
            "detection": self.detection,
            "opsec": self.opsec,
            "reliability": self.reliability,
            "tags": list(self.tags),
            "steps": list(self.steps),
            "command": self.command_for("https://HOST", "TOKEN"),
        }


def _t(**kw: object) -> Technique:
    return Technique(**kw)  # type: ignore[arg-type]


# ─── catalog data: cf/data/techniques.json — parsed once, on first use ───
_DATA_DIR = Path(__file__).resolve().parent / "data"


def _from_row(row: dict[str, Any]) -> Technique:
    kw = dict(row)
    for key in ("steps", "telemetry", "tags"):
        kw[key] = tuple(kw.get(key) or ())
    return _t(**kw)  # type: ignore[arg-type]


@cache
def _catalog() -> tuple[Technique, ...]:
    with (_DATA_DIR / "techniques.json").open(encoding="utf-8") as fh:
        return tuple(_from_row(row) for row in json.load(fh))


@cache
def _tech_map() -> dict[str, Technique]:
    return {t.id: t for t in _catalog()}


def __getattr__(name: str) -> object:
    """Lazy catalog — the map resolves on first access, not at import."""
    if name == "TECHNIQUES":
        return _tech_map()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def known_ids() -> list[str]:
    return list(_tech_map())


def get(technique_id: str) -> Technique:
    tech = _tech_map().get(technique_id)
    if tech is None:
        raise KeyError(
            f"unknown technique {technique_id!r} — try `clickfix.py technique list`"
        )
    return tech


def find(
    surface: str = "",
    category: str = "",
    query: str = "",
    serveable: bool | None = None,
    tag: str = "",
) -> list[Technique]:
    out: list[Technique] = []
    for tech in _tech_map().values():
        if surface and tech.surface != surface:
            continue
        if category and tech.category != category:
            continue
        if serveable is not None and (tech.kind is not None) != serveable:
            continue
        if tag and tag not in tech.tags:
            continue
        if query:
            blob = f"{tech.id} {tech.name} {tech.opsec} {tech.detection} {' '.join(tech.tags)}"
            if query.lower() not in blob.lower():
                continue
        out.append(tech)
    return out


def table(rows: Iterable[Technique] | None = None) -> list[dict[str, object]]:
    return [
        {
            "id": t.id,
            "surface": t.surface,
            "category": t.category,
            "kind": t.kind or "-",
            "clipboard": "yes" if t.clipboard else "no",
            "reliability": t.reliability,
            "mitre": t.mitre or "-",
            "name": t.name,
        }
        for t in (rows if rows is not None else _tech_map().values())
    ]


def markdown() -> str:
    lines = ["# clickfix technique catalog", ""]
    for surface in SURFACES:
        rows = [t for t in _tech_map().values() if t.surface == surface]
        if not rows:
            continue
        lines.append(f"## {surface}")
        lines.append("")
        for t in rows:
            kind = t.kind or "operator infra"
            lines.append(f"### {t.id} — {t.name}")
            lines.append(f"- surface: {t.surface} / category: {t.category}")
            lines.append(f"- delivery: {kind} · min os: {t.min_os} · reliability: {t.reliability}/5")
            lines.append(f"- mitre: {t.mitre or 'n/a'}")
            lines.append(f"- command: `{t.command_for('https://HOST', 'TOKEN')}`")
            lines.append(f"- steps: {' → '.join(t.steps)}")
            lines.append(f"- telemetry: {', '.join(t.telemetry)}")
            lines.append(f"- detection: {t.detection}")
            lines.append(f"- opsec: {t.opsec}")
            lines.append("")
    return "\n".join(lines)


def validate() -> list[str]:
    """Self-check used by the test suite — keeps the catalog honest."""
    problems: list[str] = []
    for tech in _tech_map().values():
        if tech.surface not in SURFACES:
            problems.append(f"{tech.id}: bad surface {tech.surface}")
        if tech.category not in CATEGORIES:
            problems.append(f"{tech.id}: bad category {tech.category}")
        if tech.kind is not None and tech.kind not in KINDS:
            problems.append(f"{tech.id}: unknown stager kind {tech.kind}")
        if len(tech.steps) < 3:
            problems.append(f"{tech.id}: needs at least 3 steps")
        if not 1 <= tech.reliability <= 5:
            problems.append(f"{tech.id}: reliability out of range")
        if tech.kind is None and tech.category != "defense" and not any(
            k in tech.template for k in ("{url}", "{host}", "{exe}")
        ):
            problems.append(f"{tech.id}: template has no placeholder")
        if tech.kind is not None and tech.template:
            problems.append(f"{tech.id}: kind techniques must not carry a template")
        if tech.mitre and not tech.mitre.startswith("T"):
            problems.append(f"{tech.id}: bad mitre id {tech.mitre}")
    return problems


# ─── sigma export — one detection rule per serveable technique ───

# kind → (binary, extra commandline keywords a blue team should watch for)
_SIGMA_BIN: dict[str, tuple[str, tuple[str, ...]]] = {
    "ps": ("powershell.exe", ("-nop", "iex")),
    "psenc": ("powershell.exe", ("-enc",)),
    "irm": ("powershell.exe", ("irm", "invoke-restmethod")),
    "curl": ("curl.exe", ("|powershell",)),
    "certutil": ("certutil.exe", ("-urlcache",)),
    "bitsadmin": ("bitsadmin.exe", ("/transfer",)),
    "hta": ("mshta.exe", (".hta",)),
    "sct": ("regsvr32.exe", ("scrobj.dll", "/i:")),
}


def _sigma_rule(tech: Technique) -> str:
    bin_name, keywords = _SIGMA_BIN.get(tech.kind or "", ("powershell.exe", ()))
    kw_lines = "\n".join(
        f"        - CommandLine|contains|all: '{kw}'" for kw in keywords
    ) or "        - CommandLine|contains: 'placeholder'"
    mitre = tech.mitre or "T1059"
    tid, sub = (mitre.split(".") + [""])[:2]
    technique_id = f"{tid}.{sub}" if sub else tid
    return f"""title: redveil — {tech.id} — {tech.name}
id: rv-{tech.id}
status: experimental
description: >
  {tech.detection}
references:
  - mitre: {tech.mitre or 'n/a'}
author: redveil framework
date: {time.strftime('%Y/%m/%d')}
tags:
  - attack.{technique_id.lower()}
logsource:
  category: process_creation
  product: windows
detection:
  sel_parent:
    ParentImage|endswith: '\\\\explorer.exe'
    Image|endswith: '\\\\{bin_name}'
  sel_cmd:
{kw_lines}
  condition: sel_parent and sel_cmd
falsepositives:
  - helpdesk instructing a user through the run dialog
level: high
"""


def sigma_rules(serveable_only: bool = True) -> str:
    """YAML document per technique — ready to drop in a sigma stack."""
    docs = [
        _sigma_rule(t)
        for t in _tech_map().values()
        if t.kind or not serveable_only
    ]
    return "---\n".join(docs)
