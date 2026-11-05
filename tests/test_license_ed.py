# language: Python 3.11+, file: tests/test_license_ed.py
# *Ed25519 module (validated against pyca when present) + CFIX2 key lifecycle*
import os

import pytest

import cf.ed25519 as ed
import cf.license as lic
from cf.license import KEY_PREFIX, LicenseError, issue, parse


# ─── ed25519 module ───


def test_ed25519_roundtrip_and_determinism():
    seed = ed.generate_seed()
    pub = ed.public_key(seed)
    msg = b"license-payload-1"
    sig = ed.sign(seed, msg)
    assert ed.verify(pub, msg, sig)
    assert ed.sign(seed, msg) == sig  # RFC 8032 signing is deterministic
    assert not ed.verify(pub, msg + b"!", sig)
    assert not ed.verify(ed.public_key(ed.generate_seed()), msg, sig)


def test_ed25519_malformed_fails_closed():
    seed = ed.generate_seed()
    pub = ed.public_key(seed)
    sig = ed.sign(seed, b"m")
    assert not ed.verify(pub, b"m", b"short")            # 8 bytes
    assert not ed.verify(b"short", b"m", sig)            # 6-byte pub
    bad = bytearray(sig); bad[31] ^= 0xFF                # R point garbage
    assert not ed.verify(pub, b"m", bytes(bad))
    assert not ed.verify(pub, b"m", sig[:32] + b"\xff" * 32)  # s >= L
    with pytest.raises(ValueError):
        ed.sign(b"tiny-seed", b"m")


def test_ed25519_tamper_every_byte_of_sig():
    """One bit flip sweeps the whole signature — no partial acceptance."""
    seed = ed.generate_seed()
    pub = ed.public_key(seed)
    sig = ed.sign(seed, b"m")
    for i in range(64):
        bad = bytearray(sig)
        bad[i] ^= 1
        assert not ed.verify(pub, b"m", bytes(bad)), f"byte {i} accepted"


def test_ed25519_cross_check_against_pyca():
    """Validated against the pyca/cryptography reference when installed —
    skipped on clean-room installs (no crypto dep in the project)."""
    crypto = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    seed = ed.generate_seed()
    pub = ed.public_key(seed)
    assert pub == (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes_raw()
    )
    msg = os.urandom(77)
    sig = ed.sign(seed, msg)
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)  # raises if bad

    back = Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    assert ed.verify(pub, msg, back)


# ─── license integration ───


def test_license_issue_parse_roundtrip(license_mint):
    key, _ = issue("pro", licensee="bb", days=30)
    parts = key.split(".")
    assert parts[0] == KEY_PREFIX
    # signature is 64 bytes of Ed25519, not 32 of HMAC
    raw_sig = lic._b64url_decode(parts[2])
    assert len(raw_sig) == 64
    parsed = parse(key)
    assert parsed.tier == "pro"
    assert parsed.licensee == "bb"
    assert parsed.active
    assert parsed.key == key


def test_license_rejects_legacy_and_stray_sigs(license_mint):
    """Old HMAC scheme dies at the dead prefix; a well-formed CFIX2 key
    carrying a 32-byte 'sig' (old HMAC digest length) fails closed."""
    fake_payload = lic._b64url(b'{"tier":"pro","licensee":"evil"}')
    with pytest.raises(LicenseError):
        parse(f"CFIX1.{fake_payload}.{lic._b64url(os.urandom(32))}")
    with pytest.raises(LicenseError):
        parse(f"{KEY_PREFIX}.{fake_payload}.{lic._b64url(os.urandom(32))}")
    with pytest.raises(LicenseError):
        parse(f"{KEY_PREFIX}.{fake_payload}.{lic._b64url(os.urandom(64))}")


def test_license_rejects_wrong_mint_pair(license_mint):
    key, _ = issue("trial", now=1_700_000_000.0)
    # re-sign the same payload with a DIFFERENT seed than the fixture's
    from cf import ed25519

    rogue = ed.generate_seed()
    parts = key.split(".")
    rogue_sig = lic._b64url(ed.sign(rogue, parts[1].encode("ascii")))
    with pytest.raises(LicenseError):
        parse(f"{parts[0]}.{parts[1]}.{rogue_sig}")


def test_license_issue_rejects_bad_seed(monkeypatch, license_mint):
    monkeypatch.setenv("REDVEIL_LICENSE_SEED", "zz-not-hex")
    with pytest.raises(LicenseError):
        issue("pro", now=1_700_000_000.0)
    monkeypatch.setenv("REDVEIL_LICENSE_SEED", "ab" * 10)  # wrong length
    with pytest.raises(LicenseError):
        issue("pro", now=1_700_000_000.0)


def test_license_issue_requires_seed(monkeypatch, license_mint):
    """Production contract: no seed env == no minting, actionable message."""
    monkeypatch.delenv("REDVEIL_LICENSE_SEED", raising=False)
    with pytest.raises(LicenseError) as excinfo:
        issue("pro", now=1_700_000_000.0)
    assert "minting key not configured" in str(excinfo.value)


def test_license_payload_tamper_caught(license_mint):
    """Swap the payload, keep the real signature — must fail closed."""
    key, _ = issue("pro", licensee="real", now=1_700_000_000.0)
    _prefix, _payload, sig = key.split(".")
    forged_payload = lic._b64url(
        b'{"tier":"team","licensee":"real","issued":0,"expires":0,"seats":1}'
    )
    with pytest.raises(LicenseError):
        parse(f"{_prefix}.{forged_payload}.{sig}")


# ─── cli surface ───


def test_license_cli_issue_verifies(tmp_path, license_mint):
    from cf.cli import Cli

    db = str(tmp_path / "l.db")
    assert Cli(["--db", db, "license", "issue", "--tier", "trial",
                "--licensee", "X"]).run() == 0
    # issue only mints when the environment carries the vendor seed


def test_license_cli_issue_fails_closed_without_seed(
    tmp_path, monkeypatch, license_mint
):
    from cf.cli import Cli

    db = str(tmp_path / "l2.db")
    monkeypatch.delenv("REDVEIL_LICENSE_SEED", raising=False)
    assert Cli(["--db", db, "license", "issue", "--tier", "trial"]).run() == 1
    assert Cli(["--db", db, "license", "verify",
                "CFIX2.garbage.garbage"]).run() == 1
