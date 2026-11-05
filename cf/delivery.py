# language: Python 3.11+, file: cf/delivery.py
# *SaaS notification delivery — lure rides the provider's own mail pipeline*
from __future__ import annotations

import asyncio
import inspect
import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from .http import HttpClient, Rate, get_client
from .store import Store

LOG = logging.getLogger("clickfix.delivery")


class SaaSNotifyDelivery:
    """The lure leaves as notification@slack.com / drive-shares-noreply@google.com
    — SPF/DKIM/DMARC belong to the provider, so inbox filters see a clean header.

    Providers: slack, teams, gdrive, notion, docusign, dropbox, figma, sharepoint.
    """

    PROVIDERS: ClassVar[dict[str, dict[str, Any]]] = {
        "slack": {
            "endpoint": "https://slack.com/api/",
            "from_domain": "notification@slack.com",
            "auth": "user OAuth token (xoxp-) or bot token (xoxb-)",
            "rate": (5, 60.0),
            "flow": [
                "1. create free workspace",
                "2. conversations.create (private) -> channel id",
                "3. chat.postMessage with the lure",
                "4. conversations.invite users=[target_email]",
                "5. target sees 'X invited you to #channel' from Slack",
            ],
        },
        "teams": {
            "endpoint": "https://graph.microsoft.com/v1.0/",
            "from_domain": "no-reply@teams.mail.microsoft.com",
            "auth": "AAD app token with Chat.Create, User.Invite.All",
            "rate": (60, 60.0),
            "flow": [
                "1. AAD app registration + consent",
                "2. POST /invitations -> target_email",
                "3. target sees the Teams invite",
            ],
        },
        "gdrive": {
            "endpoint": "https://www.googleapis.com/drive/v3/",
            "from_domain": "drive-shares-noreply@google.com",
            "auth": "OAuth scope drive",
            "rate": (50, 60.0),
            "flow": [
                "1. create a Doc holding the lure",
                "2. permissions.create share with target_email",
                "3. Google sends 'X shared a document with you'",
            ],
        },
        "notion": {
            "endpoint": "https://api.notion.com/v1/",
            "from_domain": "notify@mail.notion.so",
            "auth": "Notion integration token",
            "rate": (3, 1.0),
            "flow": [
                "1. create page with the lure",
                "2. invite target_email through the integration",
                "3. Notion mails the notification",
            ],
        },
        "docusign": {
            "endpoint": "https://demo.docusign.net/restapi/v2.1/",
            "from_domain": "dse@docusign.net",
            "auth": "OAuth JWT grant (free demo account)",
            "rate": (20, 60.0),
            "flow": [
                "1. free demo account",
                "2. envelope with signer=target_email",
                "3. DocuSign mails 'Please DocuSign: X'",
            ],
        },
        "dropbox": {
            "endpoint": "https://api.dropboxapi.com/2/",
            "from_domain": "no-reply@dropbox.com",
            "auth": "access token, scope sharing.write",
            "rate": (50, 10.0),
            "flow": [
                "1. upload the lure file",
                "2. sharing/add_file_member with target_email",
                "3. Dropbox mails the share",
            ],
        },
        "figma": {
            "endpoint": "https://api.figma.com/v1/",
            "from_domain": "notifications@figma.com",
            "auth": "Figma personal access token",
            "rate": (30, 60.0),
            "flow": [
                "1. create a Figma file holding the lure",
                "2. invite target_email as viewer",
                "3. Figma mails the invite",
            ],
        },
        "sharepoint": {
            "endpoint": "https://graph.microsoft.com/v1.0/sites/{site}/",
            "from_domain": "no-reply@sharepointonline.com",
            "auth": "AAD app token Sites.ReadWrite.All, Files.ReadWrite.All",
            "rate": (60, 60.0),
            "flow": [
                "1. create the SharePoint document",
                "2. drives/{id}/items/{id}/invite",
                "3. SharePoint mails the invitation",
            ],
        },
    }

    def __init__(
        self,
        store: Store,
        campaign_id: str,
        provider: str,
        token: str,
        api_base: str | None = None,
        http: HttpClient | None = None,
    ) -> None:
        self.store = store
        self.cid = campaign_id
        self.provider = provider
        self.token = token
        self.spec = self.PROVIDERS.get(provider)
        if not self.spec:
            raise ValueError(f"unsupported provider: {provider}")
        self.api_base = api_base or self.spec["endpoint"]
        self.http = http or get_client()
        limit, period = self.spec.get("rate", (30, 60.0))
        self.rate = Rate(limit, period)

    # ─── transport ───
    async def _req(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        headers: dict | None = None,
        data: bytes | None = None,
    ) -> dict[str, Any]:
        if path.startswith("http"):
            url = path
        else:
            # /-insensitive on both ends — provider bases carry path
            # segments (/v1/, /restapi/v2.1/) so plain concatenation lies
            url = self.api_base.rstrip("/") + "/" + path.lstrip("/")
        hdrs: dict[str, str] = dict(headers or {})
        # caller headers always win; the json default only fills the gap
        if json_body is not None and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/json"
        if self.provider == "notion":
            hdrs.setdefault("Notion-Version", "2022-06-28")
        res = await self.http.request(
            method,
            url,
            headers=hdrs,
            json_body=json_body,
            data=data,
            auth=f"Bearer {self.token}",
            rate=self.rate,
            rate_key=f"saas:{self.provider}",
        )
        return {"status": res["status"], "body": res.get("body"),
                "ok": res.get("ok", False), "error": res.get("error")}

    # ─── providers ───
    async def deliver_slack(
        self, target_email: str, channel_name: str, message: str
    ) -> dict[str, Any]:
        cr = await self._req(
            "POST",
            "conversations.create",
            {"name": channel_name[:80], "is_private": True},
        )
        ch = (cr.get("body") or {}).get("channel") or {}
        cid = ch.get("id")
        if not cid:
            return {"ok": False, "stage": "create", "resp": cr}
        pm = await self._req(
            "POST", "chat.postMessage", {"channel": cid, "text": message}
        )
        # conversations.invite wants member ids, not raw addresses
        look = await self._req(
            "POST", "users.lookupByEmail", {"email": target_email}
        )
        user_id = ((look.get("body") or {}).get("user") or {}).get("id")
        invite_target = user_id or target_email
        inv = await self._req(
            "POST",
            "conversations.invite",
            {"channel": cid, "users": [invite_target]},
        )
        ok = bool(pm.get("ok")) and bool(inv.get("ok"))
        return {
            "ok": ok,
            "channel_id": cid,
            "invite": inv.get("body"),
            "post": pm.get("body"),
        }

    async def deliver_teams(
        self, target_email: str, invite_text: str, redirect_url: str
    ) -> dict[str, Any]:
        body = {
            "invitedUserEmailAddress": target_email,
            "invitedUserDisplayName": target_email.split("@")[0][:64],
            "inviteRedirectUrl": redirect_url,
            "sendInvitationMessage": True,
            "invitedUserMessageInfo": {
                "customizedMessageBody": invite_text,
                "messageLanguage": "en-US",
            },
        }
        res = await self._req("POST", "invitations", body)
        res["ok"] = res["status"] in (200, 201)
        return res

    async def deliver_gdrive(
        self, target_email: str, doc_title: str, doc_body: str, link_url: str
    ) -> dict[str, Any]:
        doc = await self._req(
            "POST",
            "https://docs.googleapis.com/v1/documents",
            {"title": doc_title},
        )
        doc_id = (doc.get("body") or {}).get("documentId")
        if not doc_id:
            return {"ok": False, "stage": "create", "resp": doc}
        upd = await self._req(
            "POST",
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            {
                "requests": [
                    {
                        "insertText": {
                            "location": {"index": 1},
                            "text": f"{doc_body}\n\n{link_url}",
                        }
                    }
                ]
            },
        )
        share = await self._req(
            "POST",
            f"https://www.googleapis.com/drive/v3/files/{doc_id}/permissions",
            {"type": "user", "role": "reader", "emailAddress": target_email},
        )
        return {
            "ok": bool(share.get("ok")),
            "doc_id": doc_id,
            "insert": upd.get("status"),
            "share": share.get("body"),
        }

    async def deliver_notion(
        self, target_email: str, page_title: str, content_md: str, link_url: str
    ) -> dict[str, Any]:
        pg = await self._req(
            "POST",
            "pages",
            {
                "parent": {"type": "workspace", "workspace": True},
                "properties": {"title": [{"text": {"content": page_title}}]},
                "children": [
                    {
                        "object": "block",
                        "type": "paragraph",
                        "paragraph": {
                            "rich_text": [
                                {
                                    "type": "text",
                                    "text": {
                                        "content": f"{content_md}\n{link_url}"
                                    },
                                }
                            ]
                        },
                    }
                ],
            },
        )
        page_id = (pg.get("body") or {}).get("id")
        if not page_id:
            return {"ok": False, "stage": "create", "resp": pg}
        # Notion exposes no public invite endpoint — share is a workspace action
        return {
            "ok": True,
            "page_id": page_id,
            "note": "share the page with the target from the integration UI",
            "notification_from": "notify@mail.notion.so",
        }

    async def deliver_docusign(
        self,
        target_email: str,
        target_name: str,
        doc_name: str,
        pdf_b64: str,
        subject: str = "Please DocuSign: Contract",
    ) -> dict[str, Any]:
        env = {
            "emailSubject": subject,
            "documents": [
                {
                    "documentBase64": pdf_b64,
                    "name": doc_name,
                    "fileExtension": "pdf",
                    "documentId": "1",
                }
            ],
            "recipients": {
                "signers": [
                    {
                        "email": target_email,
                        "name": target_name,
                        "recipientId": "1",
                        "routingOrder": "1",
                    }
                ]
            },
            "status": "sent",
        }
        res = await self._req("POST", "accounts/self/envelopes", env)
        res["ok"] = res["status"] in (200, 201)
        return res

    async def deliver_figma(
        self,
        target_email: str,
        project_id: str,
        share_message: str = "Shared with you",
    ) -> dict[str, Any]:
        """Figma has no file-create API — the operator pre-creates the file
        in a project and this adds the target as a viewer (e-mail invite)."""
        res = await self._req(
            "POST",
            f"projects/{project_id}/members",
            {"email": target_email, "role": "viewer"},
        )
        return {
            "ok": res["status"] in (200, 201),
            "project_id": project_id,
            "resp": res.get("body"),
        }

    async def deliver_dropbox(
        self,
        target_email: str,
        file_path: str,
        share_message: str = "Shared with you",
    ) -> dict[str, Any]:
        content = await asyncio.to_thread(Path(file_path).read_bytes)
        up = await self._req(
            "POST",
            "https://content.dropboxapi.com/2/files/upload",
            headers={
                "Dropbox-API-Arg": json.dumps(
                    {
                        "path": f"/{Path(file_path).name}",
                        "mode": "add",
                        "autorename": True,
                        "mute": False,
                    }
                ),
                "Content-Type": "application/octet-stream",
            },
            data=content,
        )
        path = (up.get("body") or {}).get("path_display")
        if not path:
            return {"ok": False, "stage": "upload", "resp": up}
        res = await self._req(
            "POST",
            "https://api.dropboxapi.com/2/sharing/add_file_member",
            {
                "file": path,
                "members": [{".tag": "email", "email": target_email}],
                "custom_message": share_message,
                "quiet": False,
                "access": "viewer",
            },
        )
        res["ok"] = bool(res.get("ok"))
        return res

    async def deliver_sharepoint(
        self,
        site_id: str,
        item_id: str,
        target_email: str,
        role: str = "write",
        message: str = "",
    ) -> dict[str, Any]:
        res = await self._req(
            "POST",
            f"sites/{site_id}/drive/items/{item_id}/invite",
            {
                "recipients": [{"email": target_email}],
                "message": message,
                "requireSignIn": True,
                "sendInvitation": True,
                "roles": [role],
            },
        )
        res["ok"] = bool(res.get("ok"))
        return res

    # ─── dispatch ───
    async def deliver(self, target_email: str, **kwargs: Any) -> dict[str, Any]:
        fn = getattr(self, f"deliver_{self.provider}", None)
        if fn is None:
            return {"ok": False, "reason": f"no handler for {self.provider}"}
        bid = str(kwargs.get("bid", ""))
        # only pass parameters the handler declares — no more TypeError storms
        sig = inspect.signature(fn)
        accepts_var_kw = any(
            p.kind is inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )
        if not accepts_var_kw:
            kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
        try:
            res = await fn(target_email, **kwargs)
        except TypeError as exc:
            return {"ok": False, "reason": f"arg mismatch: {exc}"}
        except Exception as exc:  # noqa: BLE001 — provider failures are data
            LOG.warning("delivery %s failed: %s", self.provider, exc)
            res = {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
        try:
            self.store.log_event(
                bid,
                self.cid,
                f"saas_delivery_{self.provider}",
                json.dumps(
                    {"target": target_email, "result": res},
                    ensure_ascii=False,
                    default=str,
                )[:2000],
            )
        except Exception:
            LOG.debug("event log skipped", exc_info=True)
        return res

    # ─── orchestration ───
    async def run_batch(
        self,
        targets: list[dict[str, Any]],
        concurrency: int = 4,
    ) -> dict[str, Any]:
        sem = asyncio.Semaphore(max(1, concurrency))

        async def one(t: dict[str, Any]) -> dict[str, Any]:
            email = t.get("email", "")
            extra = {k: v for k, v in t.items() if k not in ("email", "status")}
            async with sem:
                result = await self.deliver(email, **extra)
                return {"email": email, "result": result}

        results = await asyncio.gather(
            *(one(t) for t in targets), return_exceptions=True
        )
        sent = 0
        failed = 0
        out: list[dict[str, Any]] = []
        for t, r in zip(targets, results):
            if isinstance(r, Exception):
                # exceptions escape without an email — attribute them to the
                # target that produced them or batch triage is guesswork
                failed += 1
                out.append(
                    {
                        "email": t.get("email", ""),
                        "ok": False,
                        "reason": f"{type(r).__name__}: {r}",
                    }
                )
                continue
            if r["result"].get("ok"):
                sent += 1
            else:
                failed += 1
            out.append(r)
        return {"sent": sent, "failed": failed, "results": out}

    @staticmethod
    def provider_playbook() -> dict[str, Any]:
        return {
            name: {
                "from": spec["from_domain"],
                "auth": spec["auth"],
                "rate": f"{spec['rate'][0]}/{spec['rate'][1]:.0f}s",
                "flow": spec["flow"],
            }
            for name, spec in SaaSNotifyDelivery.PROVIDERS.items()
        }
