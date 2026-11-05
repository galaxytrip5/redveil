# language: Python 3.11+, file: tests/test_cli_fixes.py
# *arg parsing rules, tier gates, signed beacon commands — cli surface*
import json

import pytest

from cf.cli import Cli, _num, parse_args
from cf.c2 import SIG_HEX, sign_command, verify_signed
from cf.http import _redact_url


# ─── parse_args ───


def test_boolean_flag_never_consumes_positional():
    pos, flags = parse_args(["status", "mycamp", "--json"])
    assert pos == ["status", "mycamp"]
    assert flags == {"json": True}


def test_boolean_flag_explicit_equals_still_true():
    pos, flags = parse_args(["status", "--json=1", "x"])
    assert pos == ["status", "x"]
    assert flags["json"] in (True, "1")


def test_scalar_flag_last_value_wins():
    _, flags = parse_args(["--port", "1", "--port", "2"])
    assert flags["port"] == "2"


def test_list_flags_accumulate():
    _, flags = parse_args(["--field", "a", "--field", "b"])
    assert flags["field"] == ["a", "b"]


def test_equals_form_splits_once():
    _, flags = parse_args(["--url", "http://h/l?x=1", "extra"])
    assert flags["url"] == "http://h/l?x=1"
    pos, _ = parse_args(["a"])
    assert pos == ["a"]


# ─── _num ───


def test_num_casts():
    assert _num({"days": "5"}, "days", 0, int) == 5
    assert _num({}, "days", 7, int) == 7


def test_num_bad_value_raises_system_exit():
    with pytest.raises(SystemExit) as exc:
        _num({"days": "x"}, "days", 0, int)
    assert "invalid --days" in str(exc.value)


# ─── unknown campaign surfaces an error value ───


def test_status_unknown_campaign_errors_clean(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "status", "ghost-campaign"]).run() == 1
    captured = capsys.readouterr()
    assert "unknown" in (captured.out + captured.err).lower()


def test_report_unknown_campaign_errors_clean(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "report", "ghost"]).run() == 1
    captured = capsys.readouterr()
    assert "unknown" in (captured.out + captured.err).lower()


# ─── tier gates ───


def _activate_trial(tmp_path, monkeypatch) -> None:
    from cf.license import issue, save

    monkeypatch.setenv("CLICKFIX_LICENSE_FILE", str(tmp_path / "lic.json"))
    key, _ = issue("trial", licensee="t")
    save(key)


def test_demo_relay_command_gated(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "relay", "playbook"]).run() == 1
    captured = capsys.readouterr()
    assert "relay" in (captured.out + captured.err)


def test_trial_relay_command_gated_too(tmp_path, capsys, monkeypatch):
    _activate_trial(tmp_path, monkeypatch)
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "relay", "playbook"]).run() == 1
    captured = capsys.readouterr()
    assert "relay" in (captured.out + captured.err)


def test_pro_relay_command_runs(tmp_path, capsys, monkeypatch):
    from cf.license import issue, save

    monkeypatch.setenv("CLICKFIX_LICENSE_FILE", str(tmp_path / "lic.json"))
    key, _ = issue("pro", licensee="p")
    save(key)
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "relay", "playbook"]).run() == 0
    captured = capsys.readouterr()
    assert "aws_lambda" in captured.out


def test_demo_ext_command_gated(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "ext", "playbook"]).run() == 1
    captured = capsys.readouterr()
    assert "ext" in (captured.out + captured.err)


def test_demo_payload_command_gated(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "payload", "chain"]).run() == 1
    captured = capsys.readouterr()
    assert "payload" in (captured.out + captured.err)


# ─── signed beacon commands ───


def test_sign_command_format_and_key_binding():
    signed = sign_command("whoami", "s3cr3t")
    assert signed.startswith("whoami,sig=")
    assert len(signed.split(",sig=")[1]) == SIG_HEX
    assert signed != sign_command("whoami", "other-key")
    assert sign_command("whoami", "s3cr3t") == sign_command("whoami", "s3cr3t")


def test_verify_signed_accepts_only_exact_pair():
    signed = sign_command("net user", "k")
    assert verify_signed(signed, "k")
    assert not verify_signed("net user", "k")  # unsigned passes nowhere
    assert not verify_signed("evil,sig=" + "0" * SIG_HEX, "k")
    assert not verify_signed(signed, "wrong")


def test_beacon_sign_subcommand_prints_paste_ready(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    argv = ["--db", db, "beacon", "sign", "whoami", "--sign", "unit-key"]
    assert Cli(argv).run() == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("!whoami,sig=")
    assert len(out.split(",sig=")[1]) == SIG_HEX
    assert verify_signed(out[1:], "unit-key")


def test_beacon_sign_requires_key(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CF_C2_SIGN_KEY", raising=False)
    db = str(tmp_path / "c.db")
    assert Cli(["--db", db, "beacon", "sign", "x"]).run() == 1
    captured = capsys.readouterr()
    assert "key" in (captured.out + captured.err).lower()


# ─── output plumbing ───


def test_emit_json_consistent(tmp_path, capsys):
    from cf.cli import emit_json

    emit_json({"a": 1})
    assert json.loads(capsys.readouterr().out) == {"a": 1}


def test_token_urls_redacted_in_http_logs():
    # tokens belong to headers, never to logs — beacon sign secures the
    # commands, redaction keeps secrets off the debug line
    assert "REDACTED" in _redact_url("https://h/x?token=sesame")
