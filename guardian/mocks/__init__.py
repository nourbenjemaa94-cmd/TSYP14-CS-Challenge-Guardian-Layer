"""Stand-ins for Twin and Brain so Guardian can be demonstrated on its own.

Importing this package puts ``guardian/src`` on ``sys.path`` so that
``python -m mocks.<name>`` works from ``guardian/`` without ``PYTHONPATH``.
The package is imported before any submodule, so the path is in place before
the mocks import ``guardian.*``.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
