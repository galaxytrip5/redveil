# TODOS — open work

Ordered by what unblocks the most. An item that ships gets deleted here and
named in the commit message — this file is a queue, not an archive.

## Now

1. **Remote + first push** — no git remote is configured; `0415911`
   (production pass) and `4874176` (modular cli + data files) sit on local
   `master`. CI triggers on push/pull_request, so the workflow has never run.
   Pick the host, add the remote, push — the 3.11–3.13 matrix executes for the
   first time on that push.
2. **Windows CI leg** — `ci.yml` runs `ubuntu-latest` only; the
   Windows-specific tests (`exports_from_system_dll`, System32 lookup,
   codepage reconfigure) skip there. Add `windows-latest` to the matrix.
3. **Build gate** — `python -m build` has never run: `package-data`
   (`cf/data/*`, `gui.html`) is config-only today. Add a CI step: build the
   wheel, install it into a clean venv, render a lure and read
   `_payload_hpp()` from site-packages — the only proof the data files ship.
4. **Lint + type gate** — no `[tool.ruff]` / `[tool.mypy]` in pyproject
   despite the caches in `.gitignore`. Pin both, add a CI job, fix what falls
   out.

## Next

5. **Coverage floor** — no `pytest-cov`. Add it with a minimum set at the
   current number, then ratchet.
6. **Default state path** — `clickfix.db` (+ `-wal`/`-shm`) lands in the
   working directory, and real campaign data lives in this checkout. Decide:
   keep cwd, move to `~/.redveil/`, or make `--db` the only supported path.
7. **Config file** — env vars only today. `~/.redveil/config.toml` with
   precedence flag > env > file > default.
8. **`resolve_secret` piped-read edge** — off-tty stdin blocks on `readline()`
   if the pipe stays open without data. Either document the contract or add an
   explicit `--token-stdin` with a timeout.

## Standing constraints (not tasks)

- **`cf/stager.py` is frozen.** AV quarantined it once; the suite passes with
  it untouched. No edits unless the ticket is explicitly about that file.
- Offline-signed licensing stays offline — no activation server, ever.
- No telemetry, no phone-home, no runtime dependency on an external service.
