# language: Python 3.11+, file: cf/__main__.py
# *`python -m cf` — module entry point over cf.cli*

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
