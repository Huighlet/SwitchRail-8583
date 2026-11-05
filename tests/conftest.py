"""
Pytest session isolation for SwitchRail-8583.

`switchrail.server` opens its SQLite WAL store at import time. Point it at a
throwaway per-session database before any test module imports the server so
the test suite never reads from or writes to `switchrail_production.db`.
"""

from __future__ import annotations

import os
import tempfile

_SESSION_DB_DIR = tempfile.mkdtemp(prefix="switchrail_pytest_")
os.environ["SWITCHRAIL_DB_PATH"] = os.path.join(_SESSION_DB_DIR, "switchrail_test_session.db")
