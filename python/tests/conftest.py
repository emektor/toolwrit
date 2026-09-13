"""Make the shared fixtures importable as a plain module from every test file."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
