from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from sentry.engine.clock import FixedClock
from sentry.engine.observations import (
    AuthEventObservation,
    FileIntegrityObservation,
    NetworkObservation,
    PersistenceEntryObservation,
    ProcessObservation,
    UserAccountObservation,
)
from sentry.storage.models import Base


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture
def fixed_clock() -> FixedClock:
    return FixedClock(datetime(2026, 7, 16, 10, 0, 0, tzinfo=timezone.utc))


def make_process_observation(**overrides) -> ProcessObservation:
    defaults = dict(
        pid=1234,
        ppid=1,
        exe_path="/usr/bin/bash",
        sha256="a" * 64,
        cmdline="bash",
        user="alice",
        create_time=1000.0,
    )
    defaults.update(overrides)
    return ProcessObservation(**defaults)


def make_network_observation(**overrides) -> NetworkObservation:
    defaults = dict(
        protocol="tcp",
        laddr="0.0.0.0",
        lport=8080,
        raddr="",
        rport=0,
        status="LISTEN",
        pid=1234,
        exe_path="/usr/bin/python3",
        sha256="b" * 64,
        user="alice",
    )
    defaults.update(overrides)
    return NetworkObservation(**defaults)


def make_user_account_observation(**overrides) -> UserAccountObservation:
    defaults = dict(
        username="alice",
        uid=1000,
        gid=1000,
        home_dir="/home/alice",
        shell="/bin/bash",
        groups=("alice", "sudo"),
        is_sudoer=True,
    )
    defaults.update(overrides)
    return UserAccountObservation(**defaults)


def make_persistence_entry_observation(**overrides) -> PersistenceEntryObservation:
    defaults = dict(
        mechanism="systemd_system",
        unit_or_path="/etc/systemd/system/foo.service",
        command="/usr/bin/foo --daemon",
        owner_user="root",
        enabled=True,
    )
    defaults.update(overrides)
    return PersistenceEntryObservation(**defaults)


def make_file_integrity_observation(**overrides) -> FileIntegrityObservation:
    defaults = dict(
        path="/etc/passwd",
        sha256="c" * 64,
        size_bytes=2048,
        owner="root",
        perms_octal="644",
        mtime=datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return FileIntegrityObservation(**defaults)


def make_auth_event_observation(**overrides) -> AuthEventObservation:
    defaults = dict(
        occurred_at=datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc),
        service="sshd",
        account="root",
        source_ip="203.0.113.5",
        outcome="failure",
        raw_message="Failed password for root from 203.0.113.5 port 51000 ssh2",
    )
    defaults.update(overrides)
    return AuthEventObservation(**defaults)
