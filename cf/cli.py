# language: Python 3.11+, file: cf/cli.py
# *command surface — dispatch core + command mixins (cf.cmds_*)*
from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from typing import Any

from .cli_core import (
    _configure_streams,
    _num,
    emit_json,
    err,
    ok,
    parse_args,
    text,
)
from .cmds_admin import AdminCommands
from .cmds_apt import AptCommands
from .cmds_artifacts import ArtifactCommands
from .cmds_campaign import CampaignCommands
from .cmds_delivery import DeliveryCommands
from .cmds_generate import GenerateCommands
from .util import (
    c_bold,
    c_cyan,
    c_dim,
    c_magenta,
    c_purple,
    c_white,
    detect_color,
    set_color,
)

BANNER = """\
{purple} ██████╗ ███████╗██╗   ██╗███████╗████████╗██╗   ██╗██████╗ ███████╗{/purple}
{purple} ██╔══██╗██╔════╝██║   ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝{/purple}
{purple} ██████╔╝█████╗  ██║   ██║███████╗   ██║    ╚████╔╝ ██████╔╝█████╗{/purple}
{purple} ██╔══██╗██╔══╝  ██║   ██║╚════██║   ██║     ╚██╔╝  ██╔══██╗██╔══╝{/purple}
{purple} ██║  ██║███████╗╚██████╔╝███████║   ██║      ██║   ██║  ██║███████╗{/purple}
{purple} ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝{/purple}
{dim}                                                        v{version}{/dim}
{dim}                           red team phishing & initial access framework{/dim}
"""


def _fmt_banner(raw: str) -> str:
    replacements = {
        "{purple}": c_purple(""),
        "{/purple}": "",
        "{dim}": c_dim(""),
        "{/dim}": "",
    }
    for k, v in replacements.items():
        raw = raw.replace(k, v)
    return raw


class Cli(
    CampaignCommands,
    DeliveryCommands,
    ArtifactCommands,
    AptCommands,
    AdminCommands,
    GenerateCommands,
):
    """Dispatch core — argv parsing, store/lic access, tier gates, help.
    Command bodies live in the cf.cmds_* mixins."""

    def __init__(self, argv: list[str], db_path: str = "clickfix.db") -> None:
        self.pos, self.flags = parse_args(argv)
        self.db_path = str(self.flags.get("db") or db_path)
        self._store: Any = None
        self.owns_store = True
        self.handlers: dict[str, Callable[[], None]] = {
            "campaign": self.cmd_campaign,
            "target": self.cmd_target,
            "targets": self.cmd_target,
            "lure": self.cmd_lure,
            "generate": self.cmd_generate,
            "stager": self.cmd_stager,
            "export": self.cmd_export,
            "status": self.cmd_status,
            "serve": self.cmd_serve,
            "deliver": self.cmd_deliver,
            "sendprofile": self.cmd_sendprofile,
            "profiles": self.cmd_sendprofile,
            "webhook": self.cmd_webhook,
            "webhooks": self.cmd_webhook,
            "sessions": self.cmd_sessions,
            "beacon": self.cmd_beacon,
            "aitm": self.cmd_aitm,
            "ext": self.cmd_ext,
            "relay": self.cmd_relay,
            "payload": self.cmd_payload,
            "technique": self.cmd_technique,
            "techniques": self.cmd_technique,
            "report": self.cmd_report,
            "playbook": self.cmd_playbook,
            "access": self.cmd_access,
            "creds": self.cmd_creds,
            "lateral": self.cmd_lateral,
            "persist": self.cmd_persist,
            "collect": self.cmd_collect,
            "exfil": self.cmd_exfil,
            "opsec": self.cmd_opsec,
            "license": self.cmd_license,
            "gui": self.cmd_gui,
            "version": self.cmd_version,
            "help": self.cmd_help,
            "-h": self.cmd_help,
            "--help": self.cmd_help,
        }

    # ─── store ───
    @property
    def store(self) -> Any:
        if self._store is None:
            from .store import Store

            self._store = Store(self.db_path)
        return self._store

    @property
    def lic(self) -> Any:
        from .license import effective

        return effective(self._store)

    def _campaign(self, ref: str | None = None) -> dict[str, Any]:
        ref = ref or (self.pos[1] if len(self.pos) > 1 else "")
        if not ref:
            camps = self.store.list_campaigns()
            if len(camps) == 1:
                return camps[0]
            raise SystemExit("campaign ref required (--db or `campaign list`)")
        camp = self.store.get_campaign(ref)
        if not camp:
            raise SystemExit(f"unknown campaign: {ref}")
        return camp

    def _base(self, camp: dict[str, Any] | None = None) -> str:
        url = self.flags.get("url") or (camp or {}).get("base_url") or ""
        return str(url).rstrip("/")

    # ─── dispatch ───
    def _bad(self, usage: str) -> None:
        err(usage)
        raise SystemExit(2)

    def _feature(self, feature: str) -> None:
        """Tier gate — LicenseError (run-safe) with the upgrade path stated."""
        from .license import require_feature

        require_feature(self.lic, feature)

    def _need(self, n: int, usage: str) -> None:
        if len(self.pos) < n:
            self._bad(usage)

    def run(self) -> int:
        if not self.pos:
            self.cmd_help()
            return 0
        handler = self.handlers.get(self.pos[0])
        if handler is None:
            err(f"unknown command: {self.pos[0]}")
            self.cmd_help()
            return 2
        try:
            handler()
        except SystemExit as exc:
            code = exc.code
            if code in (0, None):
                return 0
            if isinstance(code, int):
                return code
            err(str(code))
            return 1
        except KeyboardInterrupt:
            err("interrupted")
            return 130
        except Exception as exc:  # noqa: BLE001 — CredsError/LicenseError/etc
            err(str(exc))
            return 1
        finally:
            if self.owns_store and self._store is not None:
                self._store.close()
        return 0

    # ─── help ───
    def cmd_help(self) -> None:
        from . import __version__

        text(_fmt_banner(BANNER).format(version=__version__))
        text()
        text(f"  {c_bold('usage:')} clickfix.py {c_cyan('<command>')} [options]")
        text()

        sections = [
            ("campaign", [
                ("campaign new <name>", "[--scenario S] [--kind K] [--technique T] [--url U] [--locale fr|en] [--profile F.json]"),
                ("campaign list", "all campaigns"),
                ("target add <campaign>", "[--email E] [--label L] [--kind K]"),
                ("target list <campaign>", "targets + status"),
                ("lure <campaign>", "[--token T] [--out DIR]  render lure html"),
                ("export <campaign>", "token/url/status table"),
                ("report <campaign>", "[--out FILE] [--csv FILE]  engagement report"),
                ("status [campaign]", "funnel counts + last events"),
            ]),
            ("techniques", [
                ("technique list", "[--surface S] [--category C] [--tag T] [--q TEXT] [--json]"),
                ("technique show <id>", "[--url BASE]  full telemetry + opsec notes"),
                ("technique export", "[--format md|json] [--sigma] [--out F]"),
            ]),
            ("generator", [
                ("generate <pack>", "[--channel C] [--variants N] [--seed N] [--url U] [--out DIR]  pack → bundle"),
                ("generate list", "available category packs"),
            ]),
            ("delivery & c2", [
                ("serve", "[--host H] [--port P] [--url U] [--cert C --key K] [--filter]  |  --upstream https://site.tld → reverse proxy (evilginx lite)"),
                ("deliver <provider> <campaign>", "[--token X] [--message M] [--field k=v]  |  provider=smtp → --profile P|--host H [--subject S]"),
                ("sendprofile add|list|remove <name>", "[--host H --port P] [--user U] [--from E] [--tls starttls|ssl|none]  password stays in CF_SMTP_PASS"),
                ("beacon <service> --channel C", "[--token X] [--bid ID] [--interval N] [--jitter F] [--deadman URL]"),
                ("aitm refresh|pivot|persist", "device code pivot chain"),
            ]),
            ("apt modules", [
                ("access devicecode --client-id X", "[--tenant T]  oauth device code (T1528)"),
                ("access consent --client-id X", "[--tenant T]  consent grant (T1550.001)"),
                ("access vishing", "[device_code|mfa|support]  prewritten script"),
                ("creds spray <users.txt> --password P", "o365 spray w/ lockout guard"),
                ("creds kerberoast|asrep|adcs|dpapi", "command generators w/ telemetry"),
                ("lateral <pth|winrm|wmi|sccm|gpo> <host>", "lateral movement builders"),
                ("collect <screen|files|browser|clipboard|wifi>", "collection snippets"),
                ("exfil <http|slack|rclone>", "[--url U] [--key K]  exfil builders"),
                ("opsec preflight <url>", "dns/tls/headers/ua-filter checks"),
            ]),
            ("license & gui", [
                ("license status|activate <key>|deactivate", "offline license management"),
                ("license issue --tier pro|trial|team", "vendor: generate a key — needs REDVEIL_LICENSE_SEED"),
                ("license verify <key>", "check a key without saving"),
                ("gui", "[--host H] [--port P] [--no-browser] [--no-auth]  pro dashboard"),
            ]),
            ("payload & stager", [
                ("ext build <out.zip> <c2_url> <device_id>", "[--name N]"),
                ("relay lambda|azure|client", "[args]"),
                ("payload proxy <host_dll> [outdir]", "proxy dll builder"),
                ("payload hpp", "c++ payload header"),
                ("payload chain <os> [hint]", "multi-stage chain"),
                ("payload xor <file> --token T", "encrypt stage2 w/ token key"),
                ("stager command <kind> <url>", "print a win+r command"),
                ("playbook", "[saas|c2|ext|relay|stager|scenario]"),
            ]),
        ]
        for title, cmds in sections:
            text(f"  {c_magenta(title)}")
            for cmd, desc in cmds:
                text(f"    {c_white(cmd.ljust(44))} {c_dim(desc)}")
            text()
        text(f"  {c_dim('globals:')} {c_dim('--db <path>  state file (default clickfix.db)  --no-color  disable ansi')}")
        text()

    def cmd_version(self) -> None:
        from . import __version__

        text(__version__)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    _configure_streams()
    set_color(detect_color(args))
    debug = "--debug" in args
    args = [a for a in args if a not in ("--debug", "--no-color", "--no-colour")]
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return Cli(args).run()


__all__ = [
    "Cli",
    "main",
    "parse_args",
    "emit_json",
    "_num",
    "_configure_streams",
    "ok",
]
