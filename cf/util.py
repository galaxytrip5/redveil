# language: Python 3.11+, file: cf/util.py
# *shared primitives — utf-8 io, async bridge, secret handling, tokens*
from __future__ import annotations

import asyncio
import json
import os
import secrets
import string
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

TOKEN_ALPHABET = string.ascii_lowercase + string.digits

# ─── ansi colour (auto-off on pipes, NO_COLOR, or --no-color) ───
_COLOR_ENABLED = True


def set_color(enabled: bool) -> None:
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled


def _c(code: str, s: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if _COLOR_ENABLED else s


def c_dim(s: str) -> str:
    return _c("2", s)


def c_bold(s: str) -> str:
    return _c("1", s)


def c_red(s: str) -> str:
    return _c("31", s)


def c_green(s: str) -> str:
    return _c("32", s)


def c_yellow(s: str) -> str:
    return _c("33", s)


def c_magenta(s: str) -> str:
    return _c("35", s)


def c_cyan(s: str) -> str:
    return _c("36", s)


def c_white(s: str) -> str:
    return _c("97", s)


def c_gray(s: str) -> str:
    return _c("90", s)


def c_purple(s: str) -> str:
    return _c("38;5;99", s)


def detect_color(argv: list[str]) -> bool:
    """Enable colour unless --no-color, NO_COLOR env, or not a TTY."""
    if "--no-color" in argv or "--no-colour" in argv:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def new_token(length: int = 16) -> str:
    """UnGuessable per-target identifier (url-safe, no expiry needed)."""
    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))


def write_text(path: str | Path, data: str) -> Path:
    """Windows-safe writer. cp1252 chokes on box-drawing chars in templates."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data, encoding="utf-8", newline="\n")
    return p


def json_dumps(obj: Any, indent: int | None = 2) -> str:
    return json.dumps(obj, indent=indent, ensure_ascii=False, default=str)


def run_async(coro: Coroutine[Any, Any, Any], timeout: float | None = None) -> Any:
    """Run a coroutine from sync code, including when a loop is already live
    (notebooks, async CLIs, embedded hosts) — asyncio.run() raises there.
    The shared http pool is closed inside the same loop that opened it, so
    no 'unclosed connector' warnings leak into the CLI output."""

    async def _guarded() -> Any:
        from .http import peek_client, shutdown_client

        try:
            return await (
                asyncio.wait_for(coro, timeout) if timeout else coro
            )
        finally:
            client = peek_client()
            if client is not None and client.bound_loop is asyncio.get_running_loop():
                await shutdown_client()

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_guarded())
    import threading

    holder: dict[str, Any] = {}
    result: list[Any] = []
    error: list[BaseException] = []

    def _thread() -> None:
        loop = asyncio.new_event_loop()
        try:
            task = loop.create_task(_guarded())
            holder["task"] = task
            loop.run_until_complete(task)
            result.append(task.result())
        except BaseException as exc:  # noqa: BLE001 — re-raised in caller
            error.append(exc)
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    t = threading.Thread(target=_thread, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        # calling me with a timeout means abandon the work — cancel it in its
        # own loop instead of leaving a daemon thread executing silently
        task = holder.get("task")
        if task is not None and not task.done():
            task.get_loop().call_soon_threadsafe(task.cancel)
        t.join(5)
        raise TimeoutError("async task did not finish within timeout")
    if error:
        raise error[0]
    return result[0]


def resolve_secret(cli_value: str, env_name: str, prompt: str) -> str:
    """Tokens never ride in argv by default — env first, piped stdin, prompt last."""
    if cli_value:
        return cli_value
    val = os.environ.get(env_name, "")
    if val:
        return val
    if not sys.stdin.isatty():
        # no terminal: take a piped value instead of prompting (getpass would
        # emit a GetPassWarning and still block on the same stream)
        try:
            return sys.stdin.readline().strip()
        except (OSError, ValueError):
            return ""
    try:
        import getpass

        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt, OSError, ImportError):
        return ""
