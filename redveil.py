# language: Python 3.11+, file: redveil.py
# *redveil — branded entry point (thin alias over cf.cli)*
from __future__ import annotations

import sys

from cf.cli import main

if __name__ == "__main__":
    sys.exit(main())
