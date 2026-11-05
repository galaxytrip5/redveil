# language: Python 3.11+, file: tests/test_ops_boost.py
# *no external network — capture surface: store, smtp relay, evilginx-lite proxy*
import asyncio
import socket
import threading
import time
from email.message import EmailMessage

import pytest

from cf.store import Store


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "ops.db"))
    yield s
    s.close()


def _camp(store: Store, name: str, n: int = 2):
    cid = store.create_campaign(name, base_url="http://h")
    tokens = store.add_targets(
        [{"campaign_id": cid, "email": f"u{i}@corp.tld"} for i in range(n)]
    )
    return cid, tokens


# ─── gophish-style timeline ───


def test_timeline_merges_hits_and_events(store):
    cid, tokens = _camp(store, "tl", 2)
    time.sleep(0.01)
    store.record_hit(tokens[0], "lure", ip="10.1.1.1", ua="ua-x")
    store.record_hit(tokens[1], "stager:psenc", ip="10.1.1.2")
    store.log_event("b1", cid, "smtp:ok", "u0@corp.tld")
    feed = store.timeline(cid)
    kinds = [e["kind"] for e in feed]
    assert "smtp:ok" in kinds and "lure" in kinds and "stager:psenc" in kinds
    assert len(feed) == 3
    newest = feed[0]
    assert newest["ts"] >= feed[-1]["ts"]  # newest first
    by_kind = {e["kind"]: e for e in feed}
    assert by_kind["lure"]["email"] == "u0@corp.tld"
    assert by_kind["lure"]["ip"] == "10.1.1.1"
    assert by_kind["stager:psenc"]["ip"] == "10.1.1.2"
    assert by_kind["smtp:ok"]["email"] == ""  # event rows carry no target
    assert all(e["source"] in ("hit", "event") for e in feed)


def test_timeline_unknown_campaign_and_cap(store):
    assert store.timeline("ghost") == []
    cid, tokens = _camp(store, "cap", 1)
    for i in range(10):
        store.record_hit(tokens[0], f"k{i}")
    assert len(store.timeline(cid, limit=4)) == 4


def test_timeline_limit_is_bounded(store):
    cid, tokens = _camp(store, "bound", 1)
    assert store.timeline(cid, limit=-5) == store.timeline(cid, limit=1)
    assert len(store.timeline(cid, limit=10_000)) <= 500


# ─── sending profiles ───


def test_send_profile_roundtrip(store):
    store.set_send_profile("corp", {"host": "smtp.corp.tld", "port": 465,
                                    "tls": "ssl", "user": "ops",
                                    "sender": "it@corp.tld"})
    store.set_send_profile("corp", {"host": "smtp2.corp.tld", "port": 25,
                                    "tls": "none"})
    cfg = store.get_send_profile("corp")
    assert cfg["host"] == "smtp2.corp.tld"  # upsert wins
    names = [p["name"] for p in store.list_send_profiles()]
    assert names == ["corp"]
    assert store.remove_send_profile("corp") is True
    assert store.remove_send_profile("corp") is False
    assert store.get_send_profile("corp") is None


def test_send_profile_rejects_empty_name(store):
    with pytest.raises(ValueError):
        store.set_send_profile("   ", {})


# ─── smtp module ───


def test_smtp_profile_validation():
    from cf.smtp_send import SmtpProfile

    with pytest.raises(ValueError):
        SmtpProfile(host="")
    with pytest.raises(ValueError):
        SmtpProfile(host="h", port=0)
    with pytest.raises(ValueError):
        SmtpProfile(host="h", tls="quic")
    p = SmtpProfile.from_config({"host": "h", "port": 25, "tls": "none"})
    assert p.to_config() == {"host": "h", "port": 25, "user": "",
                             "sender": "", "tls": "none"}


def test_build_message_pixel_and_headers():
    from cf.smtp_send import build_message

    msg = build_message(
        sender="IT Support <it@corp.tld>",
        to="u@corp.tld",
        subject="doc",
        body="Open {url}",
        pixel_url="http://h/t/abc.gif",
    )
    assert isinstance(msg, EmailMessage)
    assert "it@corp.tld" in msg["From"]
    assert msg["To"] == "u@corp.tld"
    assert msg["Subject"] == "doc"
    raw = msg.as_string()
    assert "http://h/t/abc.gif" in raw  # 1x1 open pixel rides the html alt
    assert "Open {url}" in raw


def test_build_message_fields_mandatory():
    from cf.smtp_send import build_message

    with pytest.raises(ValueError):
        build_message(sender="", to="x", subject="s", body="b")
    with pytest.raises(ValueError):
        build_message(sender="a<b>", to="", subject="s", body="b")


class _MiniSMTP(threading.Thread):
    """Bare-socket SMTP sink — EHLO/DATA/QUIT, records message payloads."""

    daemon = True

    def __init__(self):
        super().__init__(daemon=True)
        self.messages: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def run(self):
        conn, _ = self.sock.accept()
        with conn:
            f = conn.makefile("rwb")

            def send(s: str) -> None:
                f.write(s.encode() + b"\r\n")
                f.flush()

            send("220 mini")
            in_data = False
            buf: list[bytes] = []
            for line in f:
                if in_data:
                    if line.rstrip(b"\r\n") == b".":
                        send("250 ok")
                        in_data = False
                        self.messages.append(b"".join(buf))
                        buf = []
                    else:
                        buf.append(line)
                    continue
                cmd = line.strip().upper()
                if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                    send("250-mini")
                    send("250 OK")
                elif cmd.startswith(b"DATA"):
                    send("354 go")
                    in_data = True
                elif cmd.startswith(b"QUIT"):
                    send("221 bye")
                    break
                else:
                    send("250 OK")
        self.sock.close()


def test_smtp_sender_batch_over_local_sink(store):
    from cf.smtp_send import SmtpProfile, SmtpSender, build_message

    sink = _MiniSMTP()
    sink.start()
    profile = SmtpProfile(host="127.0.0.1", port=sink.port, tls="none",
                          sender="it@corp.tld")
    batch = [
        (f"u{i}@corp.tld",
         build_message(sender="it@corp.tld", to=f"u{i}@corp.tld",
                       subject=f"m{i}", body=f"body {i}",
                       pixel_url=f"http://h/t/t{i}.gif"))
        for i in range(3)
    ]
    outcome = SmtpSender(profile).send_batch(batch)
    time.sleep(0.2)
    assert outcome == {f"u{i}@corp.tld": True for i in range(3)}
    assert len(sink.messages) == 3


def test_smtp_sender_session_cap():
    from cf.smtp_send import SmtpProfile, SmtpSender

    sender = SmtpSender(SmtpProfile(host="h", tls="none"))
    with pytest.raises(ValueError):
        sender.send_batch([("x@y", EmailMessage())] * 501)


# ─── evilginx-lite proxy ───


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _proxy_drive(tmp_path) -> tuple[list[dict], list[dict]]:
    from aiohttp import web

    async def up_page(request: web.Request) -> web.Response:
        # self-reference the upstream's own origin — the rewrite surface
        host = request.host
        return web.Response(
            text=(
                f'<html><body><a href="http://{host}/signin2">in</a>'
                '<a href="/rel">rel</a></body></html>'
            ),
            content_type="text/html",
            headers={"Set-Cookie": "SID=abc123; Path=/"},
        )

    async def up_login(request: web.Request) -> web.Response:
        form = await request.post()
        return web.json_response({"user": form.get("user", "")})

    upstream_port = _free_port()
    up_app = web.Application()
    up_app.router.add_get("/home", up_page)
    up_app.router.add_post("/signin", up_login)
    up_runner = web.AppRunner(up_app)
    await up_runner.setup()
    site = web.TCPSite(up_runner, "127.0.0.1", upstream_port)
    await site.start()

    store = Store(str(tmp_path / "proxy.db"))

    from cf.server import LandingServer

    landing_port = _free_port()
    server = LandingServer(store, host="127.0.0.1", port=landing_port,
                           upstream=f"http://127.0.0.1:{upstream_port}")
    await server.start()
    try:
        from cf.http import HttpClient

        client = HttpClient()
        page = await client.request(
            "GET", f"http://127.0.0.1:{landing_port}/home", retries=0
        )
        assert page["status"] == 200
        body = str(page.get("body", ""))
        # the upstream's own origin points back at ours now
        assert f"127.0.0.1:{upstream_port}" not in body
        assert f"127.0.0.1:{landing_port}" in body
        post = await client.request(
            "POST", f"http://127.0.0.1:{landing_port}/signin",
            data=b"user=admin", retries=0,
        )
        assert post["status"] == 200
        await client.close()
        await asyncio.sleep(0.05)  # let the store writes flush
        all_events = list(store._all("SELECT kind, payload FROM events"))
        return all_events
    finally:
        await server.stop()
        await up_runner.cleanup()
        store.close()


def test_proxy_rewrites_and_captures(tmp_path):
    all_events = asyncio.run(_proxy_drive(tmp_path))
    kinds = {e["kind"] for e in all_events}
    assert "proxy:form" in kinds   # signin POST captured
    assert "proxy:cookie" in kinds  # SID cookie harvested
    form_events = [e for e in all_events if e["kind"] == "proxy:form"]
    assert any("user=admin" in str(e["payload"]) for e in form_events)


# ─── cli wiring ───


def test_cli_sendprofile_add_list_remove(tmp_path, monkeypatch):
    from cf.cli import Cli

    db = str(tmp_path / "cli.db")
    assert Cli(["--db", db, "sendprofile", "add", "corp",
                "--host", "mail.corp.tld", "--port", "25",
                "--tls", "none", "--from", "it@corp.tld"]).run() == 0
    assert Cli(["--db", db, "sendprofile", "list"]).run() == 0
    assert Cli(["--db", db, "sendprofile", "add", "corp"]).run() == 1
    assert Cli(["--db", db, "sendprofile", "add", "x",
                "--host", "h", "--tls", "quic"]).run() == 1
    assert Cli(["--db", db, "sendprofile", "remove", "corp"]).run() == 0
    assert Cli(["--db", db, "sendprofile", "remove", "corp"]).run() == 1


def test_cli_deliver_smtp_requires_profile_or_host(tmp_path):
    from cf.cli import Cli

    db = str(tmp_path / "cli.db")
    assert Cli(["--db", db, "campaign", "new", "p",
                "--url", "http://h"]).run() == 0
    assert Cli(["--db", db, "deliver", "smtp", "p"]).run() == 1


def test_cli_help_lists_sendprofile_and_proxy():
    from cf.cli import Cli

    assert Cli(["help"]).run() == 0


def test_gui_routes_timeline(tmp_path):
    from cf.gui import RedveilGUI

    store = Store(str(tmp_path / "gt.db"))
    gui = RedveilGUI(store, auth=False)
    app = gui.build_app()
    routes = {r.resource.canonical for r in app.router.routes()}
    assert "/api/campaigns/{cid}/timeline" in routes
    store.close()
