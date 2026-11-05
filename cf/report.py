# language: Python 3.11+, file: cf/report.py
# *engagement report — funnel, timeline, iocs, detection guidance*
from __future__ import annotations

import csv
import io
import json
import time
from typing import Any

from .stager import KINDS as STAGER_KINDS
from .store import Store
from .techniques import TECHNIQUES

_ORDER = ("created", "lured", "clicked", "delivered", "executed", "dead")


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _safe_ts(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _load(
    store: Store, campaign_id: str
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Shared preamble: status lookup, error propagation, target rows."""
    st = store.status(campaign_id)
    if st.get("error"):
        raise KeyError(str(st["error"]))
    camp = st["campaign"]
    return st, camp, store.targets(camp["id"])


def _timeline(store: Store, campaign_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {
            "ts": _safe_ts(hit.get("created_at")),
            "token": str(hit.get("token", "")),
            "kind": str(hit.get("kind", "")),
            "ip": str(hit.get("ip", "")),
            "ua": str(hit.get("ua", "")),
        }
        for hit in store.campaign_hits(campaign_id)
    ]
    rows.sort(key=lambda r: r["ts"])
    return rows


def _recommendations(
    counts: dict[str, int],
    hits: dict[str, int],
    kind: str,
    total: int,
) -> list[str]:
    out: list[str] = []
    if not counts:
        return ["no targets in this campaign yet — add one before the engagement window."]
    clicked = counts.get("clicked", 0)
    executed = counts.get("executed", 0)
    stager_keys = [f"stager:{k}" for k in STAGER_KINDS]
    if sum(hits.get(k, 0) for k in stager_keys) == 0:
        out.append(
            "no loader was fetched — the paste step never happened, or the "
            "command was truncated by the run dialog."
        )
    if clicked and executed == 0:
        out.append(
            f"victims opened the lure but nothing executed — check whether the "
            f"{kind or 'stager'} binary is blocked by asr/applocker on the estate."
        )
    if executed and executed >= total:
        out.append("full conversion — rotate the landing host before reusing the page.")
    if not out:
        out.append("funnel is healthy — keep the current chain and watch for blue-team blocks.")
    return out


def build(store: Store, campaign_id: str) -> str:
    st, camp, targets = _load(store, campaign_id)
    try:
        meta = json.loads(camp.get("meta") or "{}")
    except ValueError:
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    kind = str(meta.get("kind", ""))
    tech_id = str(meta.get("technique", ""))
    tech = TECHNIQUES.get(tech_id)
    counts = {str(k): int(v) for k, v in (st.get("by_status") or {}).items()}
    hit_counts = {str(k): int(v) for k, v in (st.get("hits") or {}).items()}
    tokens = [str(t["token"]) for t in targets]
    base = str(camp.get("base_url") or "").rstrip("/")
    timeline = _timeline(store, camp["id"])
    tech_label = f"{tech.id} ({tech.name})" if tech else (tech_id or "n/a")

    lines = [
        f"# engagement report — {camp.get('name', camp['id'])}",
        "",
        "## scope",
        "",
        f"- campaign: `{camp['id']}`",
        f"- scenario: {camp.get('scenario', '')}",
        f"- technique: {tech_label}",
        f"- delivery kind: {kind or 'n/a'}",
        f"- landing host: {base or 'unset'}",
        f"- locale: {meta.get('locale', '')}",
        f"- created: {_fmt_ts(_safe_ts(camp.get('created_at')))}",
        "",
        "## funnel",
        "",
        f"- targets: {int(st.get('targets', 0))}",
    ]
    for step in _ORDER:
        if step in counts or step == "created":
            lines.append(f"- {step}: {counts.get(step, 0)}")
    lines += ["", "## loader fetches", ""]
    if hit_counts:
        for name, n in sorted(hit_counts.items()):
            lines.append(f"- {name}: {n}")
    else:
        lines.append("- none")

    lines += ["", "## timeline", ""]
    if timeline:
        for row in timeline:
            lines.append(
                f"- {_fmt_ts(row['ts'])} {row['kind']:<16} {row['token']} "
                f"ip={row['ip'] or '-'} ua={row['ua'][:60] or '-'}"
            )
    else:
        lines.append("- no hits recorded")

    lines += ["", "## indicators", ""]
    for token in tokens:
        lines.append(f"- http lure: {base}/l/{token}" if base else f"- token: {token}")
    uas = sorted({r["ua"] for r in timeline if r["ua"]})
    ips = sorted({r["ip"] for r in timeline if r["ip"]})
    if uas:
        lines.append("")
        lines.append("user-agents:")
        lines += [f"- `{ua}`" for ua in uas]
    if ips:
        lines.append("")
        lines.append("source ips:")
        lines += [f"- `{ip}`" for ip in ips]

    lines += ["", "## detection guidance", ""]
    if tech:
        lines += [
            f"- mitre: {tech.mitre or 'n/a'}",
            f"- telemetry: {', '.join(tech.telemetry)}",
            f"- what blue teams look for: {tech.detection}",
            f"- opsec: {tech.opsec}",
        ]
    else:
        lines.append(
            "- no technique bound to this campaign — run "
            "`clickfix.py technique show <id>` for telemetry mapping."
        )

    lines += ["", "## recommendations", ""]
    lines += [f"- {r}" for r in _recommendations(counts, hit_counts, kind, len(targets))]
    return "\n".join(lines) + "\n"


def csv_rows(store: Store, campaign_id: str) -> str:
    """SIEM-friendly timeline: one row per hit, no markdown."""
    st, camp, _targets = _load(store, campaign_id)
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        ["ts", "campaign", "token", "kind", "ip", "ua", "referer", "extra"]
    )
    for hit in store.campaign_hits(camp["id"]):
        writer.writerow(
            [
                _fmt_ts(_safe_ts(hit.get("created_at"))),
                camp["id"],
                str(hit.get("token", "")),
                str(hit.get("kind", "")),
                str(hit.get("ip", "")),
                str(hit.get("ua", "")),
                str(hit.get("referer", "")) if hit.get("referer") else "",
                str(hit.get("extra", ""))[:200],
            ]
        )
    return buf.getvalue()
