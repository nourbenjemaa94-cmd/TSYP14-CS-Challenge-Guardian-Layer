"""
Guardian Package Initialization
Ensures seamless imports across tests, microservices, and scenario scripts.
"""

import sys
from pathlib import Path

# Automatically ensure src/guardian and src are in sys.path
_current_dir = Path(__file__).resolve().parent
_src_dir = _current_dir.parent

if str(_current_dir) not in sys.path:
    sys.path.insert(0, str(_current_dir))
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

__version__ = "1.0.0"
__team__ = "Triplet 07"
__author__ = "Ghaith Mnasri (Member 4) & Triplet 07 Team"

