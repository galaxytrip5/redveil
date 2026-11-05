# Contributing

Thanks for the interest. `redveil` is a small, offline-by-default Python codebase
with a single SQLite store and one pooled async HTTP client — keep additions in
that spirit.

## Layout

- `cf/` — the package. Command groups live in `cmds_*.py`; one group per file.
- `cf/data/` — shipped data (technique rows, lure scenarios, packs). JSON is
  validated at load (`pytest` renders every scenario and validates every pack).
- `tests/` — offline by default. No test opens a network socket; the network
  layer is exercised through fake transports (`tests/test_http.py`).

## Adding a pack

Packs are pure data in `cf/data/categories/*.json` (and user overrides in
`~/.clickfix/packs/`). Copy `crypto.json` as a template, edit, then run:

```bash
py -3.14 -m pytest tests/test_cf.py -k "generator"
```

The suite validates the schema and renders one variant per pack. A pack that
fails validation fails the test — keep it green.

## Style

- Header on every file: `# language: Python 3.11+, file: ...`
- Errors as values, fail closed, bounded loops, no public API renames.
- Comments only for constraints the code can't express.
- No new runtime dependencies. `aiohttp` is the only mandatory one.

## Pull requests

- One concern per PR. Include a test that fails before and passes after.
- Run `py -3.14 -m pytest` locally (163+ tests, must stay green).
- CI runs on 3.11–3.14 — match that matrix before opening.
