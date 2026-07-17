"""Observation dataclasses passed to ObservationSink.emit().

Each type carries an `identity_key` property computed from the fields that
should end one interval and start a new one on change, and a MUTABLE_FIELDS
tuple naming the fields refreshed in place when an existing open observation
is matched. See engine/sink.py for how these drive the upsert.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from sentry.engine.identity import compute_identity_key


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    pid: int
    ppid: int
    exe_path: str | None
    sha256: str | None
    cmdline: str
    user: str | None
    create_time: float  # psutil.Process.create_time(): epoch seconds, immutable per process

    MUTABLE_FIELDS: ClassVar[tuple[str, ...]] = ("sha256", "cmdline", "user")

    @property
    def identity_key(self) -> str:
        # ppid is deliberately included per spec's literal suggested tuple.
        # Known accepted consequence: orphan reparenting (parent dies, kernel
        # reparents to PID 1/a subreaper) changes ppid for an otherwise
        # unchanged process, closing the old row and opening a new one next
        # cycle. This is harmless as long as the future diff engine (task 5)
        # determines "has (exe_path, sha256) ever been seen before" (rule 1)
        # by aggregating first_seen across ALL rows sharing that pair --
        # open and closed -- rather than trusting a single row's first_seen.
        return compute_identity_key(
            "process", self.pid, self.ppid, self.exe_path or "", f"{self.create_time:.6f}"
        )


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    protocol: str  # "tcp" | "udp"
    laddr: str
    lport: int
    raddr: str  # "" if no remote peer (e.g. LISTEN)
    rport: int  # 0 if no remote peer
    status: str  # LISTEN / ESTABLISHED / ...
    pid: int | None
    exe_path: str | None
    sha256: str | None
    user: str | None

    MUTABLE_FIELDS: ClassVar[tuple[str, ...]] = ("exe_path", "sha256", "user", "status")

    @property
    def identity_key(self) -> str:
        # pid is included so a service restart that rebinds the exact same
        # port closes the old row and opens a new one, giving rule 3 a clean
        # old-owner/new-owner pair instead of silently updating in place.
        return compute_identity_key(
            "network",
            self.protocol,
            self.laddr,
            self.lport,
            self.raddr,
            self.rport,
            self.pid if self.pid is not None else -1,
        )


@dataclass(frozen=True, slots=True)
class UserAccountObservation:
    username: str
    uid: int
    gid: int
    home_dir: str | None
    shell: str | None
    groups: tuple[str, ...]  # group names this account belongs to
    is_sudoer: bool

    MUTABLE_FIELDS: ClassVar[tuple[str, ...]] = ("home_dir", "shell", "is_sudoer", "groups_json")

    @property
    def groups_json(self) -> str:
        return json.dumps(sorted(self.groups))

    @property
    def identity_key(self) -> str:
        # Group membership is part of identity: a membership change (e.g.
        # added to sudo/wheel) closes the old row and opens a new one,
        # giving rule 2 a clean before/after group-membership pair instead
        # of silently overwriting it in place.
        return compute_identity_key("user", self.username, self.uid, ",".join(sorted(self.groups)))


@dataclass(frozen=True, slots=True)
class PersistenceEntryObservation:
    mechanism: str  # systemd_system|systemd_user|cron|systemd_timer|autostart|shell_rc
    unit_or_path: str
    command: str
    owner_user: str | None
    enabled: bool | None

    MUTABLE_FIELDS: ClassVar[tuple[str, ...]] = ("command", "owner_user", "enabled")

    @property
    def command_hash(self) -> str:
        return hashlib.sha256(self.command.encode("utf-8")).hexdigest()

    @property
    def identity_key(self) -> str:
        # command_hash is part of identity: an ExecStart/command change
        # closes the old row and opens a new one, giving rule 4 a clean
        # before/after command pair.
        return compute_identity_key("persistence", self.mechanism, self.unit_or_path, self.command_hash)


@dataclass(frozen=True, slots=True)
class FileIntegrityObservation:
    path: str
    sha256: str | None
    size_bytes: int | None
    owner: str | None
    perms_octal: str | None
    mtime: datetime | None

    MUTABLE_FIELDS: ClassVar[tuple[str, ...]] = ("size_bytes", "mtime")

    @property
    def identity_key(self) -> str:
        # sha256/owner/perms_octal are all part of identity: a hash change,
        # owner change, or permission change on a watched file each close
        # the old row and open a new one, giving rule 6 the old->new pair
        # it needs for every one of its trigger types.
        return compute_identity_key(
            "file_integrity", self.path, self.sha256 or "", self.owner or "", self.perms_octal or ""
        )


@dataclass(frozen=True, slots=True)
class AuthEventObservation:
    """Not interval-shaped -- a discrete journal log line, not an entity
    with presence over time. See engine/sink.py for the append-only,
    dedup-by-event_key handling this type gets in emit()."""

    occurred_at: datetime
    service: str  # sshd | sudo | login | pam
    account: str | None
    source_ip: str | None
    outcome: str  # success | failure
    raw_message: str

    @property
    def event_key(self) -> str:
        # Natural dedup key. journalctl's --since window can overlap
        # between collection cycles (clock skew, restart), so the same log
        # line must not be inserted twice; hashing the fields that
        # uniquely identify one line is simpler than tracking a journal
        # cursor across restarts.
        return compute_identity_key(
            "auth_event",
            self.occurred_at.isoformat(),
            self.service,
            self.account or "",
            self.source_ip or "",
            self.outcome,
            self.raw_message,
        )


# Extend this union as further observation types are added.
Observation = (
    ProcessObservation
    | NetworkObservation
    | UserAccountObservation
    | PersistenceEntryObservation
    | FileIntegrityObservation
    | AuthEventObservation
)
