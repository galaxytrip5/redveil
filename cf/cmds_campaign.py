# language: Python 3.11+, file: cf/cmds_campaign.py
# *campaign lifecycle — create, targets, lure render, export, status, report*
from __future__ import annotations

import json

from pathlib import Path

from .cli_core import _exit_on, _render_kv, _render_table, err, ok, text
from .util import c_bold, c_cyan, c_dim, c_gray, c_green, c_yellow, write_text


class CampaignCommands:
    """Campaign group — composed into Cli (cf.cli); self.pos/flags/store and
    the dispatch helpers (_need/_feature/_campaign/_base) live there."""

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
