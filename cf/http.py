# language: Python 3.11+, file: cf/http.py
# *shared async http — one pooled session, retries, backoff, rate limits*
from __future__ import annotations

import asyncio
import logging
import random
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

LOG = logging.getLogger("clickfix.http")

try:
    import aiohttp
    from aiohttp import ClientConnectorError, ClientError, ClientTimeout, TCPConnector

    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover — optional dep
    aiohttp = None  # type: ignore[assignment]
    ClientConnectorError = OSError  # type: ignore[assignment,misc]
    ClientError = Exception  # type: ignore[assignment,misc]
    HAS_AIOHTTP = False

UA_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})

# body cap — a wedged or hostile endpoint must not be able to balloon RAM
MAX_BODY_BYTES = 5 * 1024 * 1024

# rate-table ceiling — after this many distinct keys, expired windows are
# pruned so long-lived daemons can't grow the dict without bound
MAX_RATE_KEYS = 256

_SECRET_PARAM = re.compile(r"token|secret|key|password", re.IGNORECASE)

_CREATE_LOCK = threading.Lock()


def _redact_url(url: str) -> str:
    "Query params carrying credentials never reach the log."
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable url>"
    if not parts.query:
        return url
    pairs = [
        (k, "REDACTED" if _SECRET_PARAM.search(k) else v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment)
    )


@dataclass(frozen=True, slots=True)
class Rate:
    """Sliding-window limiter: max `limit` requests per `period` seconds."""

    limit: int
    period: float

    def __post_init__(self) -> None:
        if self.limit < 1 or self.period <= 0:
            raise ValueError("rate must be limit>=1 and period>0")


class HttpClient:
    """Every module shares one instance. One TLS handshake, one DNS cache,
    one retry policy, one place where a 429 gets obeyed."""

    def __init__(
        self,
        *,
        timeout: float = 25.0,
        connector_limit: int = 100,
        keepalive: float = 30.0,
        dns_ttl: int = 300,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        if not HAS_AIOHTTP:
            raise RuntimeError("aiohttp is required: pip install aiohttp")
        self._timeout = ClientTimeout(total=timeout)
        self._connector_kwargs: dict[str, Any] = {
            "limit": connector_limit,
            "ttl_dns_cache": dns_ttl,
            "keepalive_timeout": keepalive,
        }
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._max_body_bytes = max_body_bytes
        self._session: aiohttp.ClientSession | None = None
        self._connector: TCPConnector | None = None
        self._session_lock = asyncio.Lock()
        self._rate_locks: dict[str, asyncio.Lock] = {}
        self._rate_window: dict[str, tuple[float, int]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self.closed = False

    @property
    def bound_loop(self) -> asyncio.AbstractEventLoop | None:
        """Loop that owns the current session/locks (None until first use)."""
        return self._loop

    def _rebind(self) -> None:
        """Sessions, connectors and locks belong to one event loop. Sync
        callers often drive this class through several asyncio.run() calls,
        so drop everything owned by the previous loop instead of crashing."""
        loop = asyncio.get_running_loop()
        if loop is self._loop:
            return
        if self._session is not None and not self._session.closed:
            # the old loop owns it — close it there as a fire-and-forget task
            # so the connector's sockets don't leak a "session dropped" warning
            old_loop = self._loop
            old_session = self._session
            if old_loop is not None and not old_loop.is_closed():
                old_loop.create_task(self._close_stale(old_session))
        self._session = None
        self._connector = None
        self._session_lock = asyncio.Lock()
        self._rate_locks = {}
        self._rate_window = {}
        self._loop = loop
        self.closed = False

    async def _close_stale(self, session: aiohttp.ClientSession) -> None:
        try:
            if not session.closed:
                await asyncio.wait_for(session.close(), timeout=10)
        except (Exception, asyncio.CancelledError):  # noqa: BLE001 — best effort
            pass

    # ─── lifecycle ───
    async def session(self) -> aiohttp.ClientSession:
        self._rebind()
        if self._session is not None and not self._session.closed:
            return self._session
        async with self._session_lock:
            if self._session is None or self._session.closed:
                self._connector = TCPConnector(**self._connector_kwargs)
                self._session = aiohttp.ClientSession(
                    connector=self._connector,
                    timeout=self._timeout,
                    headers={"User-Agent": UA_CHROME},
                    raise_for_status=False,
                )
        return self._session

    async def close(self) -> None:
        self.closed = True
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None

    # ─── rate limiting ───
    async def _acquire(self, key: str | None, rate: Rate | None) -> None:
        if not key or rate is None:
            return
        if len(self._rate_window) > MAX_RATE_KEYS:
            now = time.monotonic()
            for k in [k for k, (ws, _) in self._rate_window.items() if now - ws >= rate.period]:
                self._rate_window.pop(k, None)
                self._rate_locks.pop(k, None)
        lock = self._rate_locks.setdefault(key, asyncio.Lock())
        while True:
            async with lock:
                window_start, count = self._rate_window.get(key, (0.0, 0))
                now = time.monotonic()
                if now - window_start >= rate.period:
                    self._rate_window[key] = (now, 1)
                    return
                if count < rate.limit:
                    self._rate_window[key] = (window_start, count + 1)
                    return
                wait = rate.period - (now - window_start)
            await asyncio.sleep(max(wait, 0.01))

    # ─── core request ───
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
        data: Any = None,
        params: Mapping[str, Any] | None = None,
        auth: str | None = None,
        rate: Rate | None = None,
        rate_key: str | None = None,
        retries: int | None = None,
        timeout: float | None = None,
        expect_json: bool = False,
    ) -> dict[str, Any]:
        method = method.upper()
        sess = await self.session()
        attempts = self._max_retries if retries is None else retries
        hdrs: dict[str, str] = dict(headers or {})
        if auth:
            hdrs.setdefault("Authorization", auth)
        hdrs.setdefault("User-Agent", UA_CHROME)
        last_error = "unknown"
        attempts_used = 0
        start = time.monotonic()

        for attempt in range(attempts + 1):
            attempts_used = attempt + 1
            await self._acquire(rate_key, rate)
            try:
                # timeout=None here would mean "no timeout at all" — sit out
                # the session default instead of overriding it with None
                if timeout is not None:
                    resp_ctx = sess.request(
                        method,
                        url,
                        headers=hdrs,
                        json=json_body,
                        data=data,
                        params=params,
                        timeout=ClientTimeout(total=timeout),
                    )
                else:
                    resp_ctx = sess.request(
                        method, url, headers=hdrs, json=json_body, data=data, params=params
                    )
                async with resp_ctx as resp:
                    text = await self._read_body(resp)
                    body: Any
                    if expect_json or "json" in resp.headers.get(
                        "Content-Type", ""
                    ):
                        try:
                            body = await resp.json(content_type=None)
                        except (ValueError, TypeError, aiohttp.ContentTypeError):
                            body = text
                    else:
                        body = text
                    out: dict[str, Any] = {
                        "status": resp.status,
                        "body": body,
                        "headers": dict(resp.headers),
                        "ok": resp.status < 400,
                        "attempts": attempts_used,
                        "elapsed": round(time.monotonic() - start, 3),
                    }
                    retryable = resp.status in RETRYABLE_STATUS and (
                        method in IDEMPOTENT or resp.status == 429
                    )
                    if retryable and attempt < attempts:
                        delay = self._retry_delay(attempt, resp.headers)
                        LOG.debug(
                            "retry %s %s -> %s in %.2fs",
                            attempt + 1,
                            _redact_url(url),
                            resp.status,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue
                    return out
            except (ClientError, asyncio.TimeoutError, OSError, RuntimeError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt >= attempts:
                    break
                if not self._transport_retryable(method, exc):
                    LOG.debug(
                        "no retry for non-idempotent %s after %s",
                        method,
                        type(exc).__name__,
                    )
                    break
                delay = self._retry_delay(attempt, None)
                LOG.debug(
                    "transport retry %s %s in %.2fs",
                    attempt + 1,
                    _redact_url(url),
                    delay,
                )
                await asyncio.sleep(delay)

        return {
            "status": 0,
            "body": None,
            "headers": {},
            "ok": False,
            "attempts": attempts_used,
            "error": last_error,
            "elapsed": round(time.monotonic() - start, 3),
        }

    @staticmethod
    def _transport_retryable(method: str, exc: BaseException) -> bool:
        """Idempotent verbs retry any transport failure; POST/PUT only retry
        failures where the request provably never left this process
        (connect refused/DNS/TLS) — ordering-sensitive APIs must not be
        double-submitted by a response-time blip. ClientConnectorSSLError
        and -CertificateError subclasses ride the same isinstance hit."""
        if method in IDEMPOTENT:
            return True
        return isinstance(
            exc,
            (ClientConnectorError, aiohttp.ClientConnectorSSLError),
        )

    async def _read_body(self, resp: Any) -> str:
        raw = await resp.content.read(self._max_body_bytes + 1)
        truncated = len(raw) > self._max_body_bytes
        if truncated:
            raw = raw[: self._max_body_bytes]
        enc = "utf-8"
        try:
            enc = resp.get_encoding() or "utf-8"
        except Exception:  # noqa: BLE001 — charset junk on the wire
            enc = "utf-8"
        try:
            text = raw.decode(enc, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = raw.decode("utf-8", errors="replace")
        if truncated:
            text += f"\n[truncated at {self._max_body_bytes} bytes]"
        return text

    def _retry_delay(self, attempt: int, headers: Mapping[str, str] | None) -> float:
        if headers:
            retry_after = headers.get("Retry-After")
            if retry_after:
                try:
                    return min(float(retry_after), 30.0)
                except ValueError:
                    pass
                try:
                    when = parsedate_to_datetime(retry_after)
                    delta = (when.timestamp() - time.time()) if when else 0.0
                    return min(max(delta, 0.0), 30.0)
                except (TypeError, ValueError):
                    pass
        base = self._backoff_base * (2**attempt)
        return min(base + random.uniform(0, base * 0.5), 30.0)

    # ─── shortcuts ───
    async def get(self, url: str, **kw: Any) -> dict[str, Any]:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> dict[str, Any]:
        return await self.request("POST", url, **kw)

    async def token_get(
        self, url: str, token: str, **kw: Any
    ) -> dict[str, Any]:
        return await self.get(url, auth=f"Bearer {token}", **kw)


DEFAULT_CLIENT: HttpClient | None = None


def peek_client() -> HttpClient | None:
    """No side effects — callers must not create a client just to check."""
    return DEFAULT_CLIENT


def get_client() -> HttpClient:
    """Process-wide shared client. Lazily created so imports stay cheap."""
    global DEFAULT_CLIENT
    if DEFAULT_CLIENT is None or DEFAULT_CLIENT.closed:
        with _CREATE_LOCK:
            if DEFAULT_CLIENT is None or DEFAULT_CLIENT.closed:
                DEFAULT_CLIENT = HttpClient()
    return DEFAULT_CLIENT


async def shutdown_client() -> None:
    global DEFAULT_CLIENT
    if DEFAULT_CLIENT is not None:
        await DEFAULT_CLIENT.close()
        DEFAULT_CLIENT = None
