# language: Python 3.11+, file: cf/cmds_admin.py
# *admin — license activation, pro gui*
from __future__ import annotations

from .cli_core import _num, _render_kv, err, ok, text
from .util import c_bold, c_cyan, c_dim, c_green, c_purple, c_red, c_yellow, json_dumps, run_async


class AdminCommands:
    """Admin group — composed into Cli (cf.cli); self.pos/flags/store/lic and
    the dispatch helpers (_need/_feature/_campaign/_base) live there."""

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
