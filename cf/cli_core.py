# language: Python 3.11+, file: cf/cli_core.py
# *cli primitives — flag parsing, output rendering, stream setup, dispatch glue*
from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from .util import c_cyan, c_dim, c_green, c_red, json_dumps

# flags that never consume the next token — `status --json mycamp` must keep
# the positional; everything not listed here is scalar (last value wins)
# except LIST_FLAGS, which accumulate into a list for _as_list consumers.
BOOLEAN_FLAGS = frozenset({
    "all",
    "debug",
    "filter",
    "json",
    "no-auth",
    "no-browser",
    "no-color",
    "no-colour",
    "serveable",
    "sigma",
})
LIST_FLAGS = frozenset({"field", "only", "what"})


def text(msg: str = "") -> None:
    print(msg)


def ok(msg: str) -> None:
    print(f"{c_green('[+]')} {msg}")


def err(msg: str) -> None:
    print(f"{c_red('[-]')} {msg}", file=sys.stderr)


def emit_json(obj: Any) -> None:
    print(json_dumps(obj))


@contextmanager
def _exit_on(*exc_types: type[BaseException]) -> Iterator[None]:
    try:
        yield
    except exc_types as exc:
        raise SystemExit(str(exc).strip("'")) from None


def _num(flags: dict[str, Any], key: str, default: Any, cast: Callable[[Any], Any]) -> Any:
    raw = flags.get(key, default)
    try:
        return cast(raw)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid --{key}: {raw!r}") from None


def _beacon_exec(cmd: str) -> str:
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    ).stdout


def _configure_streams() -> None:
    """stdio defaults to the ansi codepage on windows pipes; every message
    we emit (banner, arrows, status json) is utf-8."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (ValueError, OSError):
            try:
                reconfigure(errors="replace", line_buffering=True)
            except (ValueError, OSError):
                pass


def parse_args(argv: list[str]) -> tuple[list[str], dict[str, Any]]:
    pos: list[str] = []
    flags: dict[str, Any] = {}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("--"):
            key = tok[2:]
            value: Any = True
            if "=" in key:
                key, value = key.split("=", 1)
            elif (
                key not in BOOLEAN_FLAGS
                and i + 1 < len(argv)
                and not argv[i + 1].startswith("--")
            ):
                value = argv[i + 1]
                i += 1
            if key in LIST_FLAGS:
                flags.setdefault(key, []).append(value)
            else:
                flags[key] = value
        else:
            pos.append(tok)
        i += 1
    return pos, flags


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _render_table(rows: list[dict[str, Any]]) -> str:
    """Aligned fixed-width table — no dependency, safe on any console."""
    if not rows:
        return c_dim("  (empty)")
    cols = list(rows[0].keys())
    widths = {
        c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols
    }
    head = "  ".join(c_dim(c.upper().ljust(widths[c])) for c in cols)
    sep = c_dim("  ".join("-" * widths[c] for c in cols))
    body = [
        "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols)
        for r in rows
    ]
    return "\n".join([head, sep, *body])


def _render_kv(pairs: list[tuple[str, str]]) -> None:
    """Aligned key: value block with cyan keys."""
    if not pairs:
        return
    w = max(len(k) for k, _ in pairs)
    for k, v in pairs:
        text(f"  {c_cyan(k.ljust(w))}  {v}")
