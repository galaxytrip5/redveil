# redveil

ClickFix lures, legit-service C2, SaaS delivery and initial-access tooling for
red-team engagements. Python 3.11+, single SQLite store, one pooled async HTTP
client, no mandatory external services.

## Install

```bash
python -m pip install -e ".[dev]"
```

Runtime dependency: `aiohttp`. Dev dependency: `pytest`.

## Run

```bash
python redveil.py help          # branded entry point
python clickfix.py help         # legacy entry point (same CLI)
python -m cf                    # module entry
```

All three call `cf.cli.main`. `help` lists every command group: campaign,
techniques, delivery & c2, apt modules, license & gui, payload & stager.

## Test

```bash
pytest
```

Tests are offline by default: no test opens a network socket. The network layer
is exercised through fake transports (`tests/test_http.py`).

| file | covers |
|---|---|
| `tests/test_cf.py` | core — store, lure, stager, techniques, report, gui, license |
| `tests/test_http.py` | pooled client — retries, backoff, rate limits, redaction |
| `tests/test_store_perf.py` | query-shape and batch-write budgets |
| `tests/test_cli_fixes.py` | dispatch regressions, signed beacon commands |

## Layout

| path | role |
|---|---|
| `cf/cli.py`, `cf/cli_core.py`, `cf/cmds_*.py` | dispatch core, flag/render helpers, six command groups |
| `cf/store.py` | SQLite persistence (WAL, single connection, RLock) |
| `cf/http.py` | one pooled async client — retries, backoff, rate limits |
| `cf/server.py` | landing server: lure, stager, hit collection, OAuth |
| `cf/lure.py`, `cf/stager.py` | lure rendering and Win+R stager builders (page + scenarios in `cf/data/`) |
| `cf/c2.py`, `cf/delivery.py`, `cf/chain.py` | legit-service C2, SaaS notification delivery, AiTM token chain |
| `cf/ext.py`, `cf/relay.py`, `cf/payload.py` | Chrome MV3 extension C2, cloud relay codegen, payload factory |
| `cf/techniques.py` | technique catalog logic — rows live in `cf/data/techniques.json`, parsed on first use, `validate()` in the test suite |
| `cf/generator.py`, `cf/cmds_generate.py` | category-pack generator — packs in `cf/data/categories/*.json`, deterministic seed, `redveil-pro` seam for premium packs + exploit chains |
| `cf/access.py`, `cf/creds.py`, `cf/lateral.py`, `cf/collect.py`, `cf/opsec.py` | apt module builders (collection + exfil snippets live in `cf/collect.py`) behind the `cmds_apt` commands |
| `cf/report.py`, `cf/gui.py` | funnel report/CSV/Sigma export and the local dashboard (`cf/gui.html`) |
| `cf/license.py` | signed license tiers, quotas, demo watermark |
| `cf/util.py` | colors, json, `resolve_secret`, `run_async` timeouts |
| `clickfix.py`, `redveil.py`, `cf/__main__.py` | entry points |
| `cf/data/` | shipped data: technique rows, lure scenarios + template, payload factory header |

## Data files

`cf/data/` ships inside the package via `[tool.setuptools.package-data]`:

| file | consumed by | load |
|---|---|---|
| `techniques.json` | `cf/techniques.py` | first `TECHNIQUES` access, cached |
| `scenarios.json` | `cf/lure.py` | module import, cached |
| `lure_template.html` | `cf/lure.py` `_template()` | first render, cached |
| `payload_factory.hpp` | `cf/payload.py` `_payload_hpp()` | first read, cached |
| `categories/*.json` | `cf/generator.py` `load_pack()` | first `generate`, validated at load, full `validate()` in the test suite |

Edit the JSON directly. The suite validates technique rows against `KINDS`
(`validate()`) and renders every scenario, so a bad row fails `pytest`.

## Tiers

| tier | campaigns | targets | features | watermark |
|---|---|---|---|---|
| demo | 2 | 5 | — | yes |
| trial (14d) | 3 | 10 | sigma, csv | no |
| pro (365d) | unlimited | unlimited | + relay, ext, payload | no |
| team (365d) | unlimited | unlimited | + multi-seat | no |

`0` means unlimited. Feature gates (`require_feature`): `report --csv`,
`technique export --sigma`, `ext`, `relay`, `payload`. Keys are offline-signed,
prefix `CFIX1` — terms in `EULA.md`, commercial notes in `SELLING.md`.

```bash
python redveil.py license status
python redveil.py license activate <key>
python redveil.py license issue --tier pro    # vendor side
```

## Configuration

| variable | effect |
|---|---|
| `CF_INGEST_KEY` | shared secret for `/ext/ingest` and `/api/v1/results` — **required** when the server binds a non-loopback host |
| `CF_C2_SIGN_KEY` | HMAC key for signed beacon commands (alternative to `--sign`) |
| `SAAS_TOKEN` | default bearer token for `saas deliver` |
| `CLICKFIX_LICENSE_FILE` | license file path (default `~/.clickfix/license.json`) |
| `C2_REAL`, `BEACON_KEY` | values baked into generated cloud-relay code |
| `NO_COLOR`, `TERM=dumb` | disable ANSI colors |

Secrets resolve in order: flag → env → piped stdin (non-tty) → prompt.

## Docs

- `EULA.md` — license terms
- `SELLING.md` — commercial notes
- `TODOS.md` — open work
- `ROADMAP.md` — planned versions
- `EDITIONS.md` — open-source core vs `redveil-pro` matrix and seams

## Version

Single source: `pyproject.toml` → `cf.__version__` must match.
