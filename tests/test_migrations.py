from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

REPO_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = REPO_ROOT / "alembic.ini"

EXPECTED_TABLES = {
    "process_observations",
    "network_observations",
    "users_groups",
    "persistence_entries",
    "file_integrity",
    "packages",
    "system_inventory",
    "alerts",
    "suppressions",
    "auth_events",
    "alembic_version",
}

EXPECTED_PARTIAL_UNIQUE_INDEXES = {
    "ux_process_observations_open_identity": "process_observations",
    "ux_network_observations_open_identity": "network_observations",
    "ux_users_groups_open_identity": "users_groups",
    "ux_persistence_entries_open_identity": "persistence_entries",
    "ux_file_integrity_open_identity": "file_integrity",
    "ux_packages_open_identity": "packages",
}


@pytest.fixture
def migrated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    monkeypatch.setenv("SENTRY_DB_PATH", str(db_path))

    cfg = Config(str(ALEMBIC_INI))
    command.upgrade(cfg, "head")

    return db_path


def test_alembic_upgrade_head_creates_expected_schema(migrated_db):
    engine = sa.create_engine(f"sqlite:///{migrated_db}")
    inspector = sa.inspect(engine)
    table_names = set(inspector.get_table_names())

    assert EXPECTED_TABLES <= table_names

    with engine.connect() as conn:
        rows = conn.execute(
            sa.text("SELECT name, sql FROM sqlite_master WHERE type = 'index'")
        ).fetchall()
    indexes_by_name = {name: sql for name, sql in rows}

    for index_name in EXPECTED_PARTIAL_UNIQUE_INDEXES:
        assert index_name in indexes_by_name, f"missing index {index_name}"
        sql = indexes_by_name[index_name]
        assert "UNIQUE" in sql
        assert "WHERE still_present = 1" in sql


def test_db_file_created_with_0600_permissions(migrated_db):
    mode = stat.S_IMODE(os.stat(migrated_db).st_mode)
    assert oct(mode) == "0o600"


def test_alembic_downgrade_base_is_clean(migrated_db):
    cfg = Config(str(ALEMBIC_INI))
    command.downgrade(cfg, "base")

    engine = sa.create_engine(f"sqlite:///{migrated_db}")
    inspector = sa.inspect(engine)
    table_names = set(inspector.get_table_names()) - {"alembic_version"}
    assert table_names == set()
