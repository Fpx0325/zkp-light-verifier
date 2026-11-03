"""Runtime configuration shared by the command line and HTTP service."""

import os
from pathlib import Path

MAX_BATCH_SIZE = 32
MAX_LOG_PAGE = 100
MAX_BODY_BYTES = 128 * 1024


def log_path() -> Path:
    return Path(os.environ.get("ZKP_LOG_DB") or "log/verification.sqlite3")
