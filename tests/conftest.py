# language: Python 3.11+, file: tests/conftest.py
# *shared test path setup — makes `import cf` work without sys.path hacks per file*

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
