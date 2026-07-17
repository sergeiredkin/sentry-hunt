from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

APP_NAME = "sentry"
_ENV_OVERRIDE = "SENTRY_DB_PATH"


def resolve_db_path() -> Path:
    """Resolve the state DB path (spec §4.1: default ~/.local/share/<appname>/state.db).

    Honors SENTRY_DB_PATH so tests and future systemd unit overrides don't
    need to touch the real home directory.
    """
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "share" / APP_NAME / "state.db"


def db_url(path: Path | None = None) -> str:
    return f"sqlite:///{path or resolve_db_path()}"


def ensure_state_db_path(path: Path) -> Path:
    """Create the parent dir (0700) and the DB file (0600) if missing, and
    re-assert 0600 on an existing file. Must run before any engine/connection
    opens the file, from both app bootstrap and Alembic's env.py.

    Uses os.open with an explicit mode instead of touch()+chmod() so the
    file's permissions are correct atomically, with no window where a
    world-readable file exists before being locked down.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
    else:
        os.chmod(path, 0o600)
    return path


def make_engine(path: Path | None = None, **kwargs) -> Engine:
    resolved = path or resolve_db_path()
    ensure_state_db_path(resolved)
    return create_engine(db_url(resolved), **kwargs)
