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

## Test

```bash
pytest
```

Tests are offline by default: no test opens a network socket. The network layer
is exercised through fake transports (`tests/test_http.py`).

## Layout

| path | role |
|---|---|
| `cf/cli.py` | command dispatch, rendering, flags |
| `cf/store.py` | SQLite persistence (WAL, single connection, RLock) |
| `cf/http.py` | one pooled async client — retries, backoff, rate limits |
| `cf/server.py` | landing server: lure, stager, hit collection, OAuth |
| `cf/lure.py`, `cf/stager.py` | lure rendering and Win+R stager builders |
| `cf/c2.py`, `cf/delivery.py`, `cf/chain.py` | legit-service C2, SaaS notification delivery, AiTM token chain |
| `cf/ext.py`, `cf/relay.py`, `cf/payload.py` | Chrome MV3 extension C2, cloud relay codegen, payload factory |
| `cf/techniques.py` | the technique catalog, validated against `KINDS` at startup |
| `cf/report.py`, `cf/gui.py` | funnel report/CSV/Sigma export and the local dashboard |
| `cf/license.py` | signed license tiers, quotas, demo watermark |
| `tests/` | offline suite (`test_cf.py` core, plus per-area regression files) |

## Configuration

| variable | effect |
|---|---|
| `CF_INGEST_KEY` | shared secret for `/ext/ingest` and `/api/v1/results` — **required** when the server binds a non-loopback host |
| `SAAS_TOKEN` | default bearer token for `saas deliver` |
| `CLICKFIX_LICENSE` / `~/.clickfix/license.json` | license key material |

## Version

Single source: `pyproject.toml` → `cf.__version__` must match.
