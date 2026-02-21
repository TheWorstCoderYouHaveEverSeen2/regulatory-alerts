"""Backward-compatibility shim — real config lives in src/regulatory_alerts/config.py.

This file exists so that alembic/env.py and scripts/ can still do `from config import get_settings`
without needing the src/ package on sys.path via setuptools install.
"""

import sys
from pathlib import Path

# Ensure the src directory is importable
_src = str(Path(__file__).resolve().parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

from regulatory_alerts.config import Settings, get_settings  # noqa: F401, E402

__all__ = ["Settings", "get_settings"]
