"""
tests/conftest.py
-----------------
Pytest configuration and fixture setup.
Ensures src and src/guardian paths are in sys.path.
"""

import sys
import os
from pathlib import Path

# Add src and src/guardian to Python path
tests_dir = Path(__file__).resolve().parent
guardian_dir = tests_dir.parent
src_dir = guardian_dir / "src"
guardian_pkg_dir = src_dir / "guardian"

for p in [str(guardian_pkg_dir), str(src_dir), str(guardian_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

