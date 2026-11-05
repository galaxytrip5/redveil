# language: Python 3.11+, file: tests/test_http.py
# *no network — pooled client, retry policy and rate table unit-tested*
import asyncio
import threading
import time

import pytest

from cf.http import (
    MAX_RATE_KEYS,
    HttpClient,
    Rate,
    _redact_url,
    get_client,
    peek_client,
)


# ─── url redaction ───


def test_redact_url_hides_secret_query_params():
    url = "https://api.telegram.org/bot123456:ABC/sendMessage?chat_id=7&text=hi"
    token_url = "https://api.telegram.org/bot123456:ABC/getUpdates?offset=5"
    assert _redact_url(url).endswith("chat_id=7&text=hi")
    assert "123456:ABC" in _redact_url(token_url)  # path creds stay on file
    assert "REDACTED" in _redact_url("https://x/y?token=zzz&k=v")
    assert _redact_url("https://x/y?token=zzz&k=v").endswith("k=v")


def test_redact_url_survives_garbage():
    assert _redact_url("") == ""


# ─── rate limiter ───


def test_rate_validation():
    with pytest.raises(ValueError):
        Rate(0, 1.0)
    with pytest.raises(ValueError):
        Rate(1, 0.0)


def test_rate_table_bounded_under_many_keys():
    """Once the window dict passes its ceiling, stale keys must drop out —
    long-lived daemons can't grow the table without bound; active keys stay.

    Fill-prune with the real clock can't drive staleness inside one test
    tick, so the stale half is backdated by hand before a new key arrives.
    """

    async def drive() -> int:
        client = HttpClient()
        rate = Rate(1, 60.0)  # everything stays fresh on the real clock
        try:
            for i in range(MAX_RATE_KEYS + 40):
                await client._acquire(f"k{i}", rate)
            assert len(client._rate_window) == MAX_RATE_KEYS + 40
            half = MAX_RATE_KEYS // 2
            for k in list(client._rate_window)[:half]:
                # backdate against the clock http.py reads — a monotonic 0.0
                # only counts as stale once the host has booted for a full
                # period, which a fresh CI VM hasn't
                client._rate_window[k] = (time.monotonic() - rate.period - 1.0, 1)
            await client._acquire("k-new", rate)
            survived = len(client._rate_window)
        finally:
            await client.close()
        return survived

    survived = asyncio.run(drive())
    assert survived < MAX_RATE_KEYS + 40
    # the stale half plus one slab of survivors — never the untouched fill
    assert survived <= MAX_RATE_KEYS + 40 - (MAX_RATE_KEYS // 2) + 1


def test_rate_window_respects_cap():
    async def drive() -> None:
        client = HttpClient()
        rate = Rate(1, 60.0)
        try:
            await client._acquire("a", rate)
            await client._acquire("a", rate)  # second inside window sleeps
            _, count = client._rate_window["a"]
            assert count == 1
        finally:
            await client.close()

    asyncio.run(drive())


# ─── retry policy ───


def test_non_idempotent_not_retried_on_ambiguous_transport_error():
    class Ambiguous(Exception):
        pass

    assert not HttpClient._transport_retryable("POST", Ambiguous("x"))
    assert not HttpClient._transport_retryable("PUT", Ambiguous("x"))


def test_idempotent_always_retried():
    class AnyError(Exception):
        pass

    assert HttpClient._transport_retryable("GET", AnyError("x"))
    assert HttpClient._transport_retryable("HEAD", AnyError("x"))


def test_post_retried_only_on_connect_phase():
    try:
        import aiohttp

        connect_err = aiohttp.ClientConnectorError
    except ImportError:  # pragma: no cover
        connect_err = OSError

    class FakeConnect(connect_err):
        pass

    fake = FakeConnect.__new__(FakeConnect)
    assert HttpClient._transport_retryable("POST", fake)

    class Ambiguous(Exception):
        pass

    assert not HttpClient._transport_retryable("POST", Ambiguous("x"))


def test_retry_delay_caps_and_parsing(monkeypatch):
    client = HttpClient()
    d1 = client._retry_delay(0, {"Retry-After": "2"})
    assert d1 == 2.0
    # HTTP-date form
    from email.utils import formatdate

    soon = formatdate(time.time() + 5, usegmt=True)
    d2 = client._retry_delay(0, {"Retry-After": soon})
    assert 0.0 <= d2 <= 5.5
    big = client._retry_delay(0, {"Retry-After": "500"})
    assert big <= 30.0
    # exponential ceiling
    assert client._retry_delay(10, None) <= 30.0


# ─── body reading ───


class _FakeContent:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    async def read(self, limit: int) -> bytes:
        return self._payload[:limit]


class _FakeResp:
    def __init__(self, payload: bytes) -> None:
        self.content = _FakeContent(payload)

    @staticmethod
    def get_encoding() -> str:
        return "utf-8"


async def _read(payload: bytes, cap: int | None = None) -> str:
    client = HttpClient() if cap is None else HttpClient(max_body_bytes=cap)
    text = await client._read_body(_FakeResp(payload))
    await client.close()
    return text


def test_body_cap_truncates():
    marker = b"A" * 128
    out = asyncio.run(_read(marker * 100, cap=64))
    assert "[truncated at 64 bytes]" in out
    assert len(out.splitlines()[0]) == 64


def test_body_under_cap_intact():
    out = asyncio.run(_read(b"hello world"))
    assert out == "hello world"


def test_get_client_thread_safe_identity():
    got: list[int] = []

    def make() -> None:
        got.append(id(get_client()))

    threads = [threading.Thread(target=make) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(got)) == 1
    assert peek_client() is not None


def test_rate_key_missing_is_noop():
    async def drive() -> None:
        client = HttpClient()
        try:
            await client._acquire(None, Rate(1, 1))  # no key → no state
            assert client._rate_window == {}
        finally:
            await client.close()

    asyncio.run(drive())
