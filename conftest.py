"""Root conftest: ensure import roots are on sys.path for pytest (mirrors pyproject pythonpath)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for sub in ("packages", "services", "apps", "."):
    p = str((ROOT / sub).resolve())
    if p not in sys.path:
        sys.path.insert(0, p)
