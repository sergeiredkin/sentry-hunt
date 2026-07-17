"""SQLAlchemy models for the sentry state DB.

Interval-pattern tables (process_observations, network_observations,
users_groups, persistence_entries, file_integrity, packages) all share the
same shape: first_seen / last_seen / still_present / identity_key (spec
§4.2). This is the core mechanism that lets snapshot mode and continuous
mode share one schema without a rewrite (spec §3).

`identity_key` must include every field whose change should be treated as
"this observation's interval ended, a new one began" -- i.e. every field a
downstream rule needs a clean before/after pair for. Fields that are purely
descriptive and never gate a rule are left mutable (overwritten in place on
update). See engine/identity.py and engine/observations.py for the concrete
per-table field lists and the reasoning behind each one.

Each interval table gets three indexes:
  - a plain index on identity_key (lookups across open+closed history)
  - a partial UNIQUE index on identity_key WHERE still_present = 1
    (enforces "at most one open row per identity" at the DB level)
  - a partial index on last_seen WHERE still_present = 1
    (cheap range scan for close_cycle's watermark UPDATE)

system_inventory is deliberately NOT interval-shaped: it's a whole-system
point-in-time snapshot re-sampled over time, not a discrete entity with
presence/absence. "Keep latest" is ORDER BY collected_at DESC LIMIT 1.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Index, Integer, String, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import DateTime, TypeDecorator


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    """Enforces spec §4.1: all timestamps UTC, timezone-aware.

    SQLite has no native tz-aware type, so this stores naive-UTC and
    reattaches tzinfo=UTC on read. Binding a naive datetime is a programming
    error and raises -- this is the single enforcement point for the whole
    app's "always tz-aware UTC" invariant.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError(f"naive datetime not allowed, got {value!r}; all timestamps must be tz-aware UTC")
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


class ProcessObservationRow(Base):
    __tablename__ = "process_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    ppid: Mapped[int] = mapped_column(Integer, nullable=False)
    exe_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cmdline: Mapped[str] = mapped_column(Text, nullable=False, default="")
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    create_time: Mapped[float] = mapped_column(nullable=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    still_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_process_observations_identity_key", "identity_key"),
        Index(
            "ux_process_observations_open_identity",
            "identity_key",
            unique=True,
            sqlite_where=text("still_present = 1"),
        ),
        Index(
            "ix_process_observations_open_last_seen",
            "last_seen",
            sqlite_where=text("still_present = 1"),
        ),
    )


class NetworkObservationRow(Base):
    __tablename__ = "network_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)  # "tcp" | "udp"
    laddr: Mapped[str] = mapped_column(String(64), nullable=False)
    lport: Mapped[int] = mapped_column(Integer, nullable=False)
    raddr: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    rport: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # LISTEN/ESTABLISHED/...
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exe_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    still_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_network_observations_identity_key", "identity_key"),
        Index(
            "ux_network_observations_open_identity",
            "identity_key",
            unique=True,
            sqlite_where=text("still_present = 1"),
        ),
        Index(
            "ix_network_observations_open_last_seen",
            "last_seen",
            sqlite_where=text("still_present = 1"),
        ),
    )


class UserAccountRow(Base):
    __tablename__ = "users_groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    uid: Mapped[int] = mapped_column(Integer, nullable=False)
    gid: Mapped[int] = mapped_column(Integer, nullable=False)
    home_dir: Mapped[str | None] = mapped_column(Text, nullable=True)
    shell: Mapped[str | None] = mapped_column(Text, nullable=True)
    groups_json: Mapped[str] = mapped_column(Text, nullable=False)  # sorted JSON list of group names
    is_sudoer: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    still_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_users_groups_identity_key", "identity_key"),
        Index(
            "ux_users_groups_open_identity",
            "identity_key",
            unique=True,
            sqlite_where=text("still_present = 1"),
        ),
        Index(
            "ix_users_groups_open_last_seen",
            "last_seen",
            sqlite_where=text("still_present = 1"),
        ),
    )


class PersistenceEntryRow(Base):
    __tablename__ = "persistence_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    # systemd_system | systemd_user | cron | systemd_timer | autostart | shell_rc
    mechanism: Mapped[str] = mapped_column(String(32), nullable=False)
    unit_or_path: Mapped[str] = mapped_column(Text, nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    owner_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    still_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_persistence_entries_identity_key", "identity_key"),
        Index(
            "ux_persistence_entries_open_identity",
            "identity_key",
            unique=True,
            sqlite_where=text("still_present = 1"),
        ),
        Index(
            "ix_persistence_entries_open_last_seen",
            "last_seen",
            sqlite_where=text("still_present = 1"),
        ),
    )


class FileIntegrityRow(Base):
    __tablename__ = "file_integrity"

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)  # null if unreadable
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    perms_octal: Mapped[str | None] = mapped_column(String(8), nullable=True)
    mtime: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    still_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_file_integrity_identity_key", "identity_key"),
        Index(
            "ux_file_integrity_open_identity",
            "identity_key",
            unique=True,
            sqlite_where=text("still_present = 1"),
        ),
        Index(
            "ix_file_integrity_open_last_seen",
            "last_seen",
            sqlite_where=text("still_present = 1"),
        ),
        Index("ix_file_integrity_path", "path"),
    )


class PackageRow(Base):
    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    package_manager: Mapped[str] = mapped_column(String(16), nullable=False)  # apt|dnf|...
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    still_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_packages_identity_key", "identity_key"),
        Index(
            "ux_packages_open_identity",
            "identity_key",
            unique=True,
            sqlite_where=text("still_present = 1"),
        ),
        Index(
            "ix_packages_open_last_seen",
            "last_seen",
            sqlite_where=text("still_present = 1"),
        ),
        Index("ix_packages_name", "name"),
    )


class AuthEventRow(Base):
    """A discrete journal auth log line (sshd/sudo/PAM/login) -- not
    interval-shaped, since a log line has no "presence over time" to track.
    Append-only: emit() dedupes on event_key (see engine/sink.py) rather
    than upserting, since journalctl's --since window can overlap between
    collection cycles. Not part of spec §4.3's original table list; added
    because rule 5 (failed-login spike / auth anomaly) needs a queryable
    history of individual auth events to compute counts over a time window
    -- the interval model has no way to represent that.
    """

    __tablename__ = "auth_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    service: Mapped[str] = mapped_column(String(32), nullable=False)  # sshd|sudo|login|pam
    account: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)  # success|failure
    raw_message: Mapped[str] = mapped_column(Text, nullable=False)
    event_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_auth_events_occurred_at", "occurred_at"),
        Index("ix_auth_events_account", "account"),
        Index("ux_auth_events_event_key", "event_key", unique=True),
    )


class SystemInventoryRow(Base):
    """Point-in-time whole-system snapshot; not interval-shaped (see module docstring)."""

    __tablename__ = "system_inventory"

    id: Mapped[int] = mapped_column(primary_key=True)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    kernel_version: Mapped[str] = mapped_column(String(255), nullable=False)
    uptime_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    cpu_count: Mapped[int] = mapped_column(Integer, nullable=False)
    cpu_model: Mapped[str | None] = mapped_column(Text, nullable=True)
    mem_total_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    disks_json: Mapped[str] = mapped_column(Text, nullable=False)  # [{mount,total,used,fstype}, ...]

    __table_args__ = (Index("ix_system_inventory_collected_at", "collected_at"),)


class AlertRow(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(8), nullable=False)  # LOW|MEDIUM|HIGH
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # active|acknowledged|suppressed_warmup|muted
    title: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_alerts_dedup_key", "dedup_key"),
        Index("ix_alerts_rule_id_created_at", "rule_id", "created_at"),
        Index("ix_alerts_status", "status"),
    )


class SuppressionRow(Base):
    __tablename__ = "suppressions"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16), nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)  # path_hash|path|hash|exact_event|rule_global
    match_value: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(16), nullable=False)  # user|system

    __table_args__ = (Index("ix_suppressions_rule_id_scope", "rule_id", "scope"),)
