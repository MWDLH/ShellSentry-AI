"""Operating-system-specific storage paths for local runtime data."""

from __future__ import annotations

import os
import sys
from pathlib import Path


APP_NAME = "ShellSentry"


def data_dir() -> Path:
    override = os.environ.get("SHELLSENTRY_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()

    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        base = Path(root) if root else Path.home() / "AppData" / "Local"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))

    return base / APP_NAME


def config_file() -> Path:
    return data_dir() / "config.json"


def history_dir() -> Path:
    return data_dir() / "history"
