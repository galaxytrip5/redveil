# language: Python 3.11+, file: cf/opsec.py
# *preflight — validate the infrastructure before the engagement starts*
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .http import get_client

PROBE_UA = "python-requests/2.32"
BENIGN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DNS_TIMEOUT = 5.0


@dataclass(slots=True, frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _split(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    host = p.hostname or ""
    scheme = p.scheme or "https"
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        # `http://h:99999` and friends — refuse the port, keep the default so
        # preflight reports a check instead of crashing on the split
        port = 443 if scheme == "https" else 80
    if not host:
        raise ValueError(f"invalid base_url: {url!r}")
    return scheme, host, port


async def check_dns(host: str) -> Check:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP),
            timeout=DNS_TIMEOUT,
        )
        addrs = sorted({info[4][0] for info in infos})
        return Check("dns", bool(addrs), ", ".join(addrs) or "no records")
    except socket.gaierror as exc:
        return Check("dns", False, str(exc))
    except asyncio.TimeoutError:
        return Check("dns", False, f"resolver timeout after {DNS_TIMEOUT:.0f}s")


async def check_tls(host: str, port: int) -> Check:
    loop = asyncio.get_running_loop()

    def probe() -> Check:
        ctx = ssl.create_default_context()
        try:
            with (
                socket.create_connection((host, port), timeout=6) as raw,
                ctx.wrap_socket(raw, server_hostname=host) as tls,
            ):
                cert = tls.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("commonName", "?")
                not_after = cert.get("notAfter", "?")
                return Check("tls", True, f"issuer={issuer} until={not_after}")
        except (OSError, ssl.SSLError) as exc:
            return Check("tls", False, str(exc))

    return await loop.run_in_executor(None, probe)


async def check_headers(base_url: str, *, path: str = "/health") -> Check:
    client = get_client()
    res = await client.request("GET", f"{base_url.rstrip('/')}{path}", retries=0)
    if not res.get("ok"):
        # a dead host must fail preflight, not earn a clean pass from empty
        # headers — res carries {"ok": False, "error": ...} on transport failure
        return Check("headers", False, res.get("error", "request failed"))
    hdrs = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
    flags = []
    if "server" in hdrs:
        flags.append(f"server={hdrs['server']}")
    if hdrs.get("access-control-allow-origin") == "*":
        flags.append("cors=wide-open")
    if "strict-transport-security" not in hdrs:
        flags.append("no-hsts")
    if hdrs.get("x-powered-by"):
        flags.append(f"x-powered-by={hdrs['x-powered-by']}")
    leaky = any(f.startswith(("cors=wide-open", "x-powered-by=")) for f in flags)
    return Check("headers", not leaky, ", ".join(flags) or "clean")


async def check_ua_filter(base_url: str) -> Check:
    """The landing must look boring to a sandbox and real to a human."""
    client = get_client()
    probe = await client.request(
        "GET", f"{base_url.rstrip('/')}/health", headers={"User-Agent": PROBE_UA}, retries=0
    )
    benign = await client.request(
        "GET", f"{base_url.rstrip('/')}/health", headers={"User-Agent": BENIGN_UA}, retries=0
    )
    if not probe.get("ok") or not benign.get("ok"):
        detail = probe.get("error", "") or benign.get("error", "") or "request failed"
        return Check("ua_filter", False, f"unreachable — {detail}")
    p_status, b_status = probe.get("status"), benign.get("status")
    p_body = str(probe.get("body") or "")
    b_body = str(benign.get("body") or "")
    if p_status != b_status or p_body != b_body:
        return Check(
            "ua_filter",
            True,
            f"sandbox={p_status} human={b_status} — filter active",
        )
    return Check(
        "ua_filter",
        False,
        "identical response for scanner and browser UA — enable --filter scanners",
    )


async def check_tls_port(host: str, port: int) -> Check:
    loop = asyncio.get_running_loop()

    def probe() -> Check:
        try:
            with socket.create_connection((host, port), timeout=4):
                return Check("tcp", True, f"{host}:{port} open")
        except OSError as exc:
            return Check("tcp", False, f"{host}:{port} {exc}")

    return await loop.run_in_executor(None, probe)


async def preflight(base_url: str) -> list[Check]:
    # every check is isolated: one crashing probe degrades to a failed Check,
    # never a dead preflight — and independent probes run concurrently
    scheme, host, port = _split(base_url)
    tasks = [check_dns(host), check_tls_port(host, port)]
    if scheme == "https":
        tasks.append(check_tls(host, port))
    tasks.extend([check_headers(base_url), check_ua_filter(base_url)])
    results = await asyncio.gather(*tasks, return_exceptions=True)
    checks: list[Check] = []
    for res in results:
        if isinstance(res, Check):
            checks.append(res)
        elif isinstance(res, Exception):
            checks.append(Check("preflight", False, str(res)))
    return checks


def format_checks(checks: list[Check]) -> str:
    from .util import c_dim, c_green, c_red

    lines = []
    for c in checks:
        if c.ok:
            mark = c_green(" ok ")
        else:
            mark = c_red("WARN")
        lines.append(f"  [{mark}] {c_dim(c.name.ljust(10))} {c.detail}")
    return "\n".join(lines)


def summary(checks: list[Check]) -> dict[str, int]:
    return {
        "total": len(checks),
        "ok": sum(1 for c in checks if c.ok),
        "warn": sum(1 for c in checks if not c.ok),
    }
