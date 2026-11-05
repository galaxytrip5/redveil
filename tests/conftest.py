# language: Python 3.11+, file: tests/conftest.py
# *shared test path setup + license minting pair for the whole suite*

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def license_mint(monkeypatch):
    """Vendor Ed25519 pair isolated to the suite: the embedded production
    public key is swapped for a fresh per-test public key and the minting
    seed rides the env var license.py reads. Production behaviour stays
    fail-closed (no seed == no issuance)."""
    from cf import ed25519
    from cf import license as lic_mod

    seed = ed25519.generate_seed()
    monkeypatch.setattr(lic_mod, "PUBLIC_KEY", ed25519.public_key(seed))
    monkeypatch.setenv("REDVEIL_LICENSE_SEED", seed.hex())
    return seed
