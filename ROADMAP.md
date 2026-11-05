# ROADMAP — redveil

Versions are the unit: every entry names the version that ships it. Work cut
from a version moves back here, never into an excuse in the changelog.

## 2.3.1 — gates (next patch)

Docs (README / TODOS / ROADMAP) ship as-is; this patch is the hardening around
them:

- `windows-latest` leg in the CI matrix
- wheel build + install-from-artifact smoke — proves `package-data` actually
  ships `cf/data/*` and `gui.html`
- ruff + mypy pinned in pyproject, running as a CI job
- coverage floor with `pytest-cov`
- first real push: matrix 3.11–3.14 executes (today only 3.14 runs locally)

## 2.4.0 — operator experience

- `technique add | validate` — author a catalog row, run `validate()`, write
  `cf/data/techniques.json` without touching code
- scenario authoring for lure pages, same shape: edit → validate → render
- `~/.redveil/config.toml`, precedence flag > env > file > default
- `--log-format json` — one line per event, stable keys, for piping into a
  collector
- self-contained HTML engagement report bundle (single file, no external
  assets)
- GUI live funnel updates instead of refresh — SSE over the aiohttp app that
  already serves `gui.html`
- lure locale table grows past fr/en (`_wait_label` / `_foot_label` hardcode
  the two)

## 2.5.0 — scale

- store migrations: `PRAGMA user_version` + stepwise upgrade paths — today
  the schema is create-if-missing only, which freezes at the first ALTER
- command plugins: entry points exposing the `cmds_*` mixin shape, so third
  parties add commands without forking the dispatch table
- SQLite FTS5 over the technique catalog and campaign events — `find()` is a
  linear scan, fine at 43 rows, not at 400
- HTTP/2 evaluation for the pooled client: aiohttp is HTTP/1.1-only, so this
  means a transport decision (stay and document, or move to httpx/hyper) —
  only worth it if a target negotiates h2 and discriminates on it
- Docker image + compose example for `serve` (certs and state as volumes)

## 3.0.0 — team mode

- make the reserved `multi-seat` feature real: per-seat keys, shared
  workspace, per-seat audit trail on store writes
- remote dashboard over the existing relay path (gui already has token auth
  plumbing)
- signed revocation list shipped inside releases — checked offline, still no
  server

## Frozen — will not do

- `cf/stager.py` — AV history; no edits outside a ticket that names it
- telemetry, phone-home, accounts — none, ever
- activation server — licensing stays offline-signed by design
