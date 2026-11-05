# language: Python 3.11+, file: cf/license.py
# *redveil offline-signed licensing — trial / pro / team tiers, demo quota, vendor issuing*
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import json_dumps, write_text

KEY_PREFIX = "CFIX1"
SIGN_SEED = hashlib.sha256(b"clickfix-license-v2-2026-standalone").digest()

TIERS: dict[str, dict[str, Any]] = {
    "demo": {
        "days": 0,
        "campaigns": 2,
        "targets": 5,
        "features": (),
        "watermark": True,
    },
    "trial": {
        "days": 14,
        "campaigns": 3,
        "targets": 10,
        "features": ("sigma", "csv"),
        "watermark": False,
    },
    "pro": {
        "days": 365,
        "campaigns": 0,
        "targets": 0,
        "features": ("sigma", "csv", "relay", "ext", "payload"),
        "watermark": False,
    },
    "team": {
        "days": 365,
        "campaigns": 0,
        "targets": 0,
        "features": ("sigma", "csv", "relay", "ext", "payload", "multi-seat"),
        "watermark": False,
    },
}


class LicenseError(RuntimeError):
    """Invalid, expired or tampered key — operator actionable."""


LOG = logging.getLogger("cf.license")

# caches: one re-verify per file change; demo tier is computed once, a
# deactivate() must clear it
_EFFECTIVE_CACHE: tuple[float, int, str, License] | None = None
_EFFECTIVE_MISSING: License | None = None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(payload_b64: str) -> str:
    return _b64url(
        hmac.new(SIGN_SEED, payload_b64.encode("ascii"), hashlib.sha256).digest()
    )


@dataclass(frozen=True, slots=True)
class License:
    tier: str
    licensee: str
    issued: float
    expires: float
    seats: int = 1
    key: str = field(default="", compare=False)

    @property
    def tier_spec(self) -> dict[str, Any]:
        return TIERS.get(self.tier, TIERS["demo"])

    @property
    def expired(self) -> bool:
        return self.expires > 0 and time.time() > self.expires

    @property
    def active(self) -> bool:
        return bool(self.tier) and not self.expired

    @property
    def watermark(self) -> bool:
        return bool(self.tier_spec.get("watermark"))

    def max_campaigns(self) -> int:
        return int(self.tier_spec["campaigns"])

    def max_targets(self) -> int:
        return int(self.tier_spec["targets"])

    def has(self, feature: str) -> bool:
        return feature in self.tier_spec["features"]

    def days_left(self) -> int:
        if self.expires <= 0:
            return 0
        return max(0, int((self.expires - time.time()) / 86400))

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "licensee": self.licensee,
            "issued": self.issued,
            "expires": self.expires,
            "seats": self.seats,
            "expired": self.expired,
            "active": self.active,
            "days_left": self.days_left(),
            "features": sorted(self.tier_spec["features"]),
            "key": self.key[:24] + "…" if self.key else "",
        }


def issue(
    tier: str = "pro",
    *,
    licensee: str = "unlicensed",
    days: int | None = None,
    seats: int = 1,
    now: float | None = None,
) -> tuple[str, License]:
    """Vendor-side key generation — only the seller runs this."""
    spec = TIERS.get(tier)
    if spec is None:
        raise LicenseError(f"unknown tier: {tier} (choose from {', '.join(TIERS)})")
    issued = now if now is not None else time.time()
    ttl = int(days if days is not None else spec["days"])
    expires = issued + ttl * 86400 if ttl > 0 else 0.0
    payload = {
        "tier": tier,
        "licensee": licensee[:80],
        "issued": round(issued, 3),
        "expires": round(expires, 3),
        "seats": max(1, int(seats)),
    }
    payload_b64 = _b64url(json.dumps(payload, sort_keys=True).encode("utf-8"))
    key = f"{KEY_PREFIX}.{payload_b64}.{_sign(payload_b64)}"
    lic = License(
        tier=tier,
        licensee=licensee[:80],
        issued=payload["issued"],
        expires=payload["expires"],
        seats=payload["seats"],
        key=key,
    )
    return key, lic


def parse(key: str) -> License:
    """Parse + verify a key. Raises on anything malformed or tampered."""
    raw = (key or "").strip()
    parts = raw.split(".")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        raise LicenseError("malformed key — expected CFIX1.<payload>.<sig>")
    _prefix, payload_b64, sig = parts
    if not (payload_b64.isascii() and sig.isascii()):
        # .encode("ascii") in _sign would raise a bare UnicodeEncodeError
        raise LicenseError("malformed key — payload and signature must be ascii")
    if not hmac.compare_digest(sig, _sign(payload_b64)):
        raise LicenseError("signature mismatch — key was tampered with")
    try:
        data: Any = json.loads(_b64url_decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise LicenseError(f"payload unreadable: {exc}") from None
    if not isinstance(data, dict):
        raise LicenseError("payload must be an object")
    tier = str(data.get("tier", ""))
    if tier not in TIERS:
        raise LicenseError(f"unknown tier in key: {tier!r}")
    lic = License(
        tier=tier,
        licensee=str(data.get("licensee", "")),
        issued=float(data.get("issued", 0)),
        expires=float(data.get("expires", 0)),
        seats=max(1, int(data.get("seats", 1))),
        key=raw,
    )
    if lic.expired:
        days = int((time.time() - lic.expires) / 86400) if lic.expires > 0 else 0
        raise LicenseError(
            f"license expired {days} day(s) ago "
            f"(tier={tier}, licensee={lic.licensee})"
        )
    return lic


def license_path(override: str | Path | None = None) -> Path:
    if override:
        return Path(override)
    env = os.environ.get("CLICKFIX_LICENSE_FILE")
    if env:
        return Path(env)
    root = Path.home() / ".clickfix"
    return root / "license.json"


def load(override: str | Path | None = None) -> License | None:
    """Return the active licence, or None (demo mode). Never raises.

    A missing file is quiet (first run); a corrupt/unreadable key logs one
    warning so a typo'd activation does not silently downgrade to demo.
    """
    path = license_path(override)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        LOG.warning("license file unreadable (%s): %s", path, exc)
        return None
    key = str(data.get("key", "")) if isinstance(data, dict) else ""
    if not key:
        return None
    try:
        return parse(key)
    except LicenseError as exc:
        LOG.warning("license rejected: %s", exc)
        return None


def save(key: str, override: str | Path | None = None) -> Path:
    lic = parse(key)  # fail fast on activation
    path = license_path(override)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text(path, json_dumps({"key": lic.key, "activated_at": time.time()}))
    return path


def deactivate(override: str | Path | None = None) -> bool:
    global _EFFECTIVE_MISSING
    path = license_path(override)
    try:
        path.unlink()
        _EFFECTIVE_MISSING = None  # force a fresh demo computation
        return True
    except OSError:
        return False


_EFFECTIVE_CACHE: tuple[float, int, str, License] | None = None


def effective(store: Any = None, override: str | Path | None = None) -> License:
    """Active licence or the implicit demo tier — the single entry point
    every quota / feature / watermark decision goes through.

    The file is stat()ed, not re-read: one HMAC verify per real change
    instead of per HTTP request (gui.py calls this per request).
    """
    global _EFFECTIVE_CACHE, _EFFECTIVE_MISSING
    try:
        st = license_path(override).stat()
        stamp: tuple[float, int, str] | None = (
            float(st.st_mtime_ns),
            st.st_size,
            str(override or ""),
        )
    except FileNotFoundError:
        stamp = None
    if stamp is None:
        # plain demo on first run — nothing to cache until a file shows up
        cached = _EFFECTIVE_MISSING
        if cached is not None:
            return cached
        lic = License(tier="demo", licensee="", issued=0.0, expires=0.0, key="")
        _EFFECTIVE_MISSING = lic
        return lic
    cached = _EFFECTIVE_CACHE
    if cached is not None and cached[:3] == stamp:
        return cached[3]
    lic: License
    loaded = load(override)
    if loaded is not None and loaded.active:
        lic = loaded
    else:
        lic = License(
            tier="demo",
            licensee="",
            issued=0.0,
            expires=0.0,
            key="",
        )
    _EFFECTIVE_CACHE = (*stamp, lic)
    return lic


def check_quota(lic: License, store: Any, campaign_id: str | None = None) -> None:
    """Raise LicenseError when the tier limit is hit — called from the CLI
    before any state-changing write."""
    max_campaigns = lic.max_campaigns()
    if max_campaigns:
        existing = store.count_campaigns()
        if existing >= max_campaigns:
            raise LicenseError(
                f"tier '{lic.tier}' allows {max_campaigns} campaign(s) — "
                "upgrade with `license activate <key>`"
            )
    if campaign_id is not None:
        max_targets = lic.max_targets()
        if max_targets:
            targets = store.count_targets(campaign_id)
            if targets >= max_targets:
                raise LicenseError(
                    f"tier '{lic.tier}' allows {max_targets} target(s) per "
                    "campaign — upgrade with `license activate <key>`"
                )


def require_feature(lic: License, feature: str) -> None:
    if not lic.has(feature):
        raise LicenseError(
            f"feature '{feature}' is not in tier '{lic.tier}' — "
            "upgrade with `license activate <key>`"
        )
