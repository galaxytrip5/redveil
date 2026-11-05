# language: Python 3.11+, file: clickfix.py
# *redveil — red team phishing & initial access framework (entry point)*
# *subsystem re-exports are lazy: `import clickfix` costs this module alone,*
# *and `python clickfix.py help` never pays for chain/c2/delivery/ext/relay*
#
# usage: python clickfix.py help

from __future__ import annotations

import importlib
import sys
from typing import Any

__all__ = [
    "AiTMEdgeChain",
    "CloudRelay",
    "ExtensionC2",
    "LegitServiceC2",
    "LureBuilder",
    "PayloadFactory",
    "SaaSNotifyDelivery",
    "Stager",
    "main",
]

_EXPORTS = {
    "AiTMEdgeChain": ("cf.chain", "AiTMEdgeChain"),
    "CloudRelay": ("cf.relay", "CloudRelay"),
    "ExtensionC2": ("cf.ext", "ExtensionC2"),
    "LegitServiceC2": ("cf.c2", "LegitServiceC2"),
    "LureBuilder": ("cf.lure", "LureBuilder"),
    "PayloadFactory": ("cf.payload", "PayloadFactory"),
    "SaaSNotifyDelivery": ("cf.delivery", "SaaSNotifyDelivery"),
    "Stager": ("cf.stager", "Stager"),
}


def __getattr__(name: str) -> Any:
    """PEP 562 lazy re-export — same pattern as cf/__init__."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    value = getattr(importlib.import_module(module_name), attr)
    globals()[name] = value
    return value


def main(argv: list[str] | None = None) -> int:
    from cf.cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
