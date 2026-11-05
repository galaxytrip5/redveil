# language: Python 3.11+, package: cf
# *redveil framework core — store, http, delivery, c2, lure, stager, server*
from __future__ import annotations

__version__ = "2.3.0"
__all__ = [
    "TECHNIQUES",
    "AiTMEdgeChain",
    "CloudRelay",
    "ExtensionC2",
    "HttpClient",
    "LandingServer",
    "LegitServiceC2",
    "LureBuilder",
    "PayloadFactory",
    "SaaSNotifyDelivery",
    "Stager",
    "Store",
    "Technique",
]


def __getattr__(name: str):
    """Lazy imports — startup cost stays proportional to the command used."""
    if name == "Store":
        from .store import Store
        return Store
    if name == "HttpClient":
        from .http import HttpClient
        return HttpClient
    if name == "SaaSNotifyDelivery":
        from .delivery import SaaSNotifyDelivery
        return SaaSNotifyDelivery
    if name == "LegitServiceC2":
        from .c2 import LegitServiceC2
        return LegitServiceC2
    if name == "AiTMEdgeChain":
        from .chain import AiTMEdgeChain
        return AiTMEdgeChain
    if name == "ExtensionC2":
        from .ext import ExtensionC2
        return ExtensionC2
    if name == "CloudRelay":
        from .relay import CloudRelay
        return CloudRelay
    if name == "PayloadFactory":
        from .payload import PayloadFactory
        return PayloadFactory
    if name == "LureBuilder":
        from .lure import LureBuilder
        return LureBuilder
    if name == "Stager":
        from .stager import Stager
        return Stager
    if name == "LandingServer":
        from .server import LandingServer
        return LandingServer
    if name == "Technique":
        from .techniques import Technique
        return Technique
    if name == "TECHNIQUES":
        from .techniques import TECHNIQUES
        return TECHNIQUES
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
