# language: Python 3.11+, file: cf/cmds_generate.py
# *category generator — pack selection, bundle emission, lure files*
from __future__ import annotations

from .cli_core import _num, emit_json, err, ok, text


class GenerateCommands:
    """generator group — composed into Cli (cf.cli); self.pos/flags and the
    dispatch helpers (_need/_feature) live there."""

    def cmd_generate(self) -> None:
        from .generator import generate, list_packs, write_bundle

        usage = (
            "generate <pack>|list [--channel C] [--variants N] [--seed N] "
            "[--url U] [--continue U] [--locale fr|en] [--out DIR] "
            "[--edr-hint H] [--c2 URL]"
        )
        self._need(2, usage)
        if self.pos[1] == "list":
            for pack_id in list_packs():
                text(pack_id)
            return

        has_chain = self.lic.has("payload")
        if not has_chain:
            err("note: payload chain needs the payload tier — bundle emitted without it")
        try:
            bundle = generate(
                self.pos[1],
                channel=str(self.flags.get("channel") or "email"),
                variants=_num(self.flags, "variants", 0, int) or None,
                seed=_num(self.flags, "seed", 0, int),
                base_url=str(self.flags.get("url") or ""),
                continue_url=str(
                    self.flags.get("continue") or "https://www.google.com"
                ),
                locale=str(self.flags.get("locale") or "fr"),
                edr_hint=str(self.flags.get("edr-hint") or ""),
                c2_url=str(self.flags.get("c2") or ""),
                include_chain=has_chain,
            )
        except FileNotFoundError as exc:
            err(str(exc))
            err("packs: " + ", ".join(list_packs()))
            raise SystemExit(1) from None
        except ValueError as exc:
            err(str(exc))
            raise SystemExit(1) from None

        out = str(self.flags.get("out") or "")
        if out:
            for name, path in write_bundle(bundle, out).items():
                ok(f"{name} → {path}")
        else:
            emit_json(bundle)
