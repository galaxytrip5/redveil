<div align="center">

# redveil

### A red-team framework for controlled delivery and engagement workflows

[![CI](https://github.com/galaxytrip5/redveil/actions/workflows/ci.yml/badge.svg)](https://github.com/galaxytrip5/redveil/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**redveil** is a Python-based framework for controlled red-team engagements, focused on ClickFix-style lures, legitimate-service C2 patterns, delivery workflows, and initial-access tooling. It is designed to support structured and traceable operations in a local-first, lightweight environment.

[Overview](#overview) · [Features](#features) · [Installation](#installation) · [Quick start](#quick-start) · [Testing](#testing) · [Documentation](#documentation)

</div>

> [!IMPORTANT]
> **Use only in authorized environments.** This project is intended for security testing and red-team exercises with explicit authorization from the relevant stakeholders. Ensure you comply with legal requirements, engagement scope, and internal policies before using it. See [EULA.md](EULA.md).

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Editions](#editions)
- [Configuration and data](#configuration-and-data)
- [Documentation](#documentation)
- [License and responsible use](#license-and-responsible-use)

## Overview

redveil is a Python 3.11+ project built around a small, reusable set of capability blocks for security operators. It integrates campaign management, technique catalogs, generated lure content, local persistence, reporting and a lightweight HTTP stack, all without requiring a mandatory external service for the core workflow.

The repository is organized around a single SQLite-backed store, a shared async HTTP client, and a modular command interface. The code structure emphasizes maintainability, local execution, validation through tests, and explicit feature boundaries between the open-source core and optional premium capabilities.

## Features

| Area | Description |
|---|---|
| **Campaign management** | Structured workflows for campaign and target-oriented operations. |
| **Technique catalog** | Built-in technique definitions, validation, and extensible data-driven content. |
| **Lure generation** | Templates, scenarios and delivery-oriented patterns that can be rendered and adapted. |
| **Delivery tooling** | Components for controlled payload and distribution flows. |
| **C2 / command flows** | Legitimate-service styled communication and logic for operational control. |
| **Reporting** | Local reporting and export-oriented functionality for results and summaries. |
| **CLI-first workflow** | Command-line entry points for broad operational control. |
| **Local-first architecture** | Local SQLite storage and a pooled async HTTP client reduce reliance on external infrastructure. |
| **Validation-focused** | Automated tests cover the main execution paths and regression safety. |

For a more detailed view of the edition boundaries and premium capabilities, see [EDITIONS.md](EDITIONS.md).

## Requirements

- Python **3.11+**
- `pip`
- A virtual environment is recommended

## Installation

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The runtime dependency is `aiohttp`. The `dev` extra installs `pytest` for local validation.

## Quick start

Display the CLI help:

```bash
python redveil.py help
```

Other entry points:

```bash
python -m cf help
python clickfix.py help
```

All of these route back to the same core CLI implementation. The help output lists the command groups and subcommands available in the current build.

Before running any operational workflow, define a clear authorization boundary, scope, environment, and documentation trail for the engagement.

## Testing

Run the test suite:

```bash
pytest
```

The repository is designed to keep tests offline by default. No test opens a network socket; the HTTP layer is exercised using mocked or fake transports.

| File | Scope |
|---|---|
| `tests/test_cf.py` | Core application behavior, persistence, scenarios, reporting, GUI and licensing |
| `tests/test_http.py` | HTTP client behavior, retries, backoff, rate limiting and redaction logic |
| `tests/test_store_perf.py` | Storage access patterns and write-performance checks |
| `tests/test_cli_fixes.py` | CLI dispatch and regression validation |
| `tests/test_ops_boost.py` | Additional operational coverage |
| `tests/test_license_ed.py` | Licensing checks and related primitives |

## Project layout

| Path | Role |
|---|---|
| `cf/cli.py`, `cf/cli_core.py`, `cf/cmds_*.py` | Command dispatch and CLI subcommand logic |
| `cf/store.py` | SQLite persistence layer |
| `cf/http.py` | Shared async HTTP client |
| `cf/lure.py`, `cf/stager.py` | Lure rendering and operation staging logic |
| `cf/techniques.py`, `cf/generator.py` | Technique catalog and data-driven generation |
| `cf/report.py`, `cf/gui.py`, `cf/gui.html` | Reporting and local dashboard experience |
| `cf/data/` | Bundled scenarios, templates and data files |
| `tests/` | Automated validation suite |
| `redveil.py`, `clickfix.py`, `cf/__main__.py` | Project entry points |

> The presence of modules in the repository does not necessarily mean that every capability is included in the OSS build. Refer to [EDITIONS.md](EDITIONS.md) for the public vs premium split.

## Editions

This project is designed around a shared codebase with multiple edition profiles. The OSS source in this repository is paired with a separate proprietary distribution for advanced capability layers. The split is documented in [EDITIONS.md](EDITIONS.md), which describes when functionality is open-source, optional, or gated by a license.

## Configuration and data

Data files live under `cf/data/` and are packaged via the configuration in `pyproject.toml`. The project is intentionally structured to let operators work with validated data definitions and JSON-driven packs rather than hardcoding functionality in multiple places.

Keep secrets and sensitive values out of the repository, logs, or generated outputs. Use ephemeral test values for demonstrations, and store real credentials according to your organization’s handling policy.

## Documentation

- [EDITIONS.md](EDITIONS.md) — open-source vs premium capability split
- [EULA.md](EULA.md) — license and usage terms
- [LICENSE](LICENSE) — project license
- [ROADMAP.md](ROADMAP.md) — planned roadmap and version direction
- [TODOS.md](TODOS.md) — current work items
- [SELLING.md](SELLING.md) — business/distribution notes

## License and responsible use

The repository is distributed under the **GNU GPL-3.0** license. Please review [LICENSE](LICENSE) for the full terms. If you are using a licensed or proprietary edition, make sure you also review any additional terms that apply to that distribution.

Use this project only within the boundaries of explicit authorization, approved scope, and applicable laws. Maintain proper documentation, minimize operational risk, and treat the resulting artifacts as controlled security tooling rather than generic software.

---

<div align="center">

Built for authorized, controlled, and documented security operations.

</div>
