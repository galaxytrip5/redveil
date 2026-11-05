<div align="center">

# redveil

### A framework for authorized security validation

[![CI](https://github.com/galaxytrip5/redveil/actions/workflows/ci.yml/badge.svg)](https://github.com/galaxytrip5/redveil/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**redveil** is a Python project for authorized, controlled security exercises. Its source combines campaign-oriented components, data-driven scenarios, local persistence, and reporting in a modular codebase.

[About](#about) · [Project structure](#project-structure) · [Development](#development) · [Responsible use](#responsible-use)

</div>

> [!WARNING]
> This repository concerns security-testing techniques that can affect real systems. Use it only in an isolated lab or under explicit written authorization, within an agreed scope and rules of engagement. This README is a project overview, not an operational deployment guide.

## About

redveil is written primarily in Python and requires Python 3.11 or newer. The repository describes a red-team framework involving simulated delivery workflows and command-and-control concepts. Those capabilities are dual-use; this project should be handled as controlled security tooling, not run against public or third-party systems without permission.

The codebase uses a local SQLite store, an asynchronous HTTP client, and a command-oriented architecture. Project data such as catalogs and scenarios is kept separately from core logic, which supports validation and maintainability.

## Project at a glance

| Component | Purpose |
|---|---|
| **Campaign data** | Organizes engagement-related state and records. |
| **Scenario and technique data** | Stores structured definitions used by project components. |
| **Local persistence** | Uses SQLite for application state. |
| **HTTP layer** | Provides shared asynchronous networking code. |
| **Reporting and interface** | Contains reporting components, a CLI, and a local dashboard. |
| **Automated tests** | Exercises core behavior and regression cases, using simulated transports for HTTP tests. |

Capabilities differ between distributions. See [EDITIONS.md](EDITIONS.md) for the documented edition boundaries.

## Project structure

| Path | Description |
|---|---|
| `cf/cli.py`, `cf/cli_core.py`, `cf/cmds_*.py` | CLI dispatch and command modules |
| `cf/store.py` | SQLite persistence |
| `cf/http.py` | Shared asynchronous HTTP client |
| `cf/techniques.py`, `cf/generator.py` | Catalog and data-driven components |
| `cf/report.py`, `cf/gui.py`, `cf/gui.html` | Reporting and local interface |
| `cf/data/` | Packaged data, scenarios, and templates |
| `tests/` | Automated tests |
| `pyproject.toml` | Package metadata and development configuration |

## Development

Requirements:

- Python 3.11 or newer
- `pip`

Create a virtual environment and install the development dependencies:

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\\Scripts\\activate
python -m pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest
```

Tests are intended to run offline by default. The HTTP tests use fake transports rather than opening network connections.

## Topics

For readers exploring defensive and authorized security work, this project relates to **security validation**, **authorized red-team exercises**, **purple teaming**, **defensive security research**, **detection engineering**, **security-awareness simulations**, **Python security tooling**, **local-first applications**, **SQLite**, and **automated testing**. These terms describe the project’s context; they do not replace the requirement for written authorization and a clearly defined test scope.

## Documentation

- [EDITIONS.md](EDITIONS.md) — edition and feature boundaries
- [EULA.md](EULA.md) — usage terms (template; not legal advice)
- [LICENSE](LICENSE) — GNU GPL-3.0 license text
- [ROADMAP.md](ROADMAP.md) — planned project work
- [TODOS.md](TODOS.md) — outstanding tasks

## Responsible use

Use this software only for systems and environments for which you have explicit authorization. Before an exercise, establish a written scope, approved test window, rules of engagement, safety contacts, and a plan for handling data and artifacts. Stop testing if activity falls outside the approved scope or causes unexpected impact.

Users are responsible for complying with applicable laws, organizational policy, and the terms of any distribution they use. Do not use this project to target systems or people without permission.

---

<div align="center">

**Authorized testing. Isolated environments. Clear scope.**

</div>
