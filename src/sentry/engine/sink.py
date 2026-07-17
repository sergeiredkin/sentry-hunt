"""ObservationSink: the push interface collectors emit into (spec §3), and
the interval-upsert logic that implements spec §4.2's three transitions:

  - observed + open match exists      -> update last_seen (+ mutable fields)
  - observed + no open match          -> insert new row, still_present=True
  - previously open, not observed     -> still_present=False, last_seen frozen

The same sink and upsert logic serve snapshot mode (this task) and
continuous mode (future, additive) -- see spec §15.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Protocol, Union

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from sentry.engine.clock import Clock, SystemClock
from sentry.engine.observations import (
    AuthEventObservation,
    FileIntegrityObservation,
    NetworkObservation,
    Observation,
    PersistenceEntryObservation,
    ProcessObservation,
    UserAccountObservation,
)
from sentry.storage.models import (
    AuthEventRow,
    Base,
    FileIntegrityRow,
    NetworkObservationRow,
    PersistenceEntryRow,
    ProcessObservationRow,
    UserAccountRow,
)


class ObservationSink(Protocol):
    """Push interface per spec §3. Collectors depend on ONLY this method."""

    def emit(self, observation: Observation) -> None: ...


@dataclass(frozen=True)
class _IntervalMapping:
    """Registry entry for an interval-shaped observation (spec §4.2):
    upserted by identity_key, closed by absence via close_cycle()."""

    model: type[Base]
    mutable_fields: tuple[str, ...]
    to_row_kwargs: Callable[[Observation], dict]


@dataclass(frozen=True)
class _AppendOnlyMapping:
    """Registry entry for a discrete-event observation (e.g. a journal
    line): no upsert, no still_present/close_cycle -- just insert-if-absent,
    deduped on a natural key computed from the event's own content."""

    model: type[Base]
    dedupe_key_attr: str  # property on the observation
    dedupe_key_column: str  # matching column on the model
    to_row_kwargs: Callable[[Observation], dict]


_Mapping = Union[_IntervalMapping, _AppendOnlyMapping]

_REGISTRY: dict[type, _Mapping] = {
    ProcessObservation: _IntervalMapping(
        model=ProcessObservationRow,
        mutable_fields=ProcessObservation.MUTABLE_FIELDS,
        to_row_kwargs=lambda o: dict(
            pid=o.pid,
            ppid=o.ppid,
            exe_path=o.exe_path,
            sha256=o.sha256,
            cmdline=o.cmdline,
            user=o.user,
            create_time=o.create_time,
            identity_key=o.identity_key,
        ),
    ),
    NetworkObservation: _IntervalMapping(
        model=NetworkObservationRow,
        mutable_fields=NetworkObservation.MUTABLE_FIELDS,
        to_row_kwargs=lambda o: dict(
            protocol=o.protocol,
            laddr=o.laddr,
            lport=o.lport,
            raddr=o.raddr,
            rport=o.rport,
            status=o.status,
            pid=o.pid,
            exe_path=o.exe_path,
            sha256=o.sha256,
            user=o.user,
            identity_key=o.identity_key,
        ),
    ),
    UserAccountObservation: _IntervalMapping(
        model=UserAccountRow,
        mutable_fields=UserAccountObservation.MUTABLE_FIELDS,
        to_row_kwargs=lambda o: dict(
            username=o.username,
            uid=o.uid,
            gid=o.gid,
            home_dir=o.home_dir,
            shell=o.shell,
            groups_json=o.groups_json,
            is_sudoer=o.is_sudoer,
            identity_key=o.identity_key,
        ),
    ),
    PersistenceEntryObservation: _IntervalMapping(
        model=PersistenceEntryRow,
        mutable_fields=PersistenceEntryObservation.MUTABLE_FIELDS,
        to_row_kwargs=lambda o: dict(
            mechanism=o.mechanism,
            unit_or_path=o.unit_or_path,
            command=o.command,
            owner_user=o.owner_user,
            enabled=o.enabled,
            identity_key=o.identity_key,
        ),
    ),
    FileIntegrityObservation: _IntervalMapping(
        model=FileIntegrityRow,
        mutable_fields=FileIntegrityObservation.MUTABLE_FIELDS,
        to_row_kwargs=lambda o: dict(
            path=o.path,
            sha256=o.sha256,
            size_bytes=o.size_bytes,
            owner=o.owner,
            perms_octal=o.perms_octal,
            mtime=o.mtime,
            identity_key=o.identity_key,
        ),
    ),
    AuthEventObservation: _AppendOnlyMapping(
        model=AuthEventRow,
        dedupe_key_attr="event_key",
        dedupe_key_column="event_key",
        to_row_kwargs=lambda o: dict(
            occurred_at=o.occurred_at,
            service=o.service,
            account=o.account,
            source_ip=o.source_ip,
            outcome=o.outcome,
            raw_message=o.raw_message,
            event_key=o.event_key,
        ),
    ),
}
# Extend this dict (and the Observation union in observations.py) when
# further observation types are added -- sink internals never need to change.


class SqlAlchemyObservationSink:
    """Concrete ObservationSink implementing the interval-upsert pattern.

    Takes an existing SQLAlchemy Session (dependency-injected -- the sink
    owns no engine/connection of its own), so tests can hand it any session
    bound to an in-memory or tmp-path SQLite DB, and the future pipeline can
    scope it to one transaction per cycle.
    """

    def __init__(self, session: Session, clock: Clock = SystemClock()):
        self._session = session
        self._clock = clock
        self._cycle_time: datetime | None = None

    def begin_cycle(self, cycle_time: datetime | None = None) -> datetime:
        """Snapshot mode: call once before a batch of collector.collect(sink)
        calls. Fixes the timestamp all emit() calls in this cycle use for
        first_seen/last_seen, and that close_cycle() uses as its watermark.
        Returns the resolved cycle_time so callers can pass it to
        close_cycle(). If never called, emit() falls back to per-call
        wall-clock time (continuous-mode-style usage, no batching)."""
        t = cycle_time or self._clock.now()
        if t.tzinfo is None:
            raise ValueError("cycle_time must be tz-aware UTC")
        self._cycle_time = t
        return t

    def emit(self, observation: Observation) -> None:
        mapping = _REGISTRY[type(observation)]
        if isinstance(mapping, _AppendOnlyMapping):
            self._emit_append_only(observation, mapping)
        else:
            self._emit_interval(observation, mapping)

    def _emit_interval(self, observation: Observation, mapping: _IntervalMapping) -> None:
        model = mapping.model
        now = self._cycle_time or self._clock.now()

        existing = self._session.execute(
            select(model).where(
                model.identity_key == observation.identity_key,
                model.still_present.is_(True),
            )
        ).scalar_one_or_none()

        if existing is not None:
            existing.last_seen = now
            for field in mapping.mutable_fields:
                setattr(existing, field, getattr(observation, field))
        else:
            row = model(
                first_seen=now,
                last_seen=now,
                still_present=True,
                **mapping.to_row_kwargs(observation),
            )
            self._session.add(row)

        # Flush (not commit) so a second emit() for the same identity within
        # this cycle sees the first emit's row via the SELECT above -- this
        # is what makes repeated/duplicate emits in one cycle collapse to a
        # single row instead of double-inserting.
        self._session.flush()

    def _emit_append_only(self, observation: Observation, mapping: _AppendOnlyMapping) -> None:
        model = mapping.model
        dedupe_value = getattr(observation, mapping.dedupe_key_attr)
        dedupe_column = getattr(model, mapping.dedupe_key_column)

        existing = self._session.execute(
            select(model).where(dedupe_column == dedupe_value)
        ).scalar_one_or_none()
        if existing is not None:
            return  # already ingested this exact event -- idempotent no-op

        row = model(**mapping.to_row_kwargs(observation))
        self._session.add(row)
        self._session.flush()

    def close_cycle(self, model: type[Base], cycle_time: datetime) -> int:
        """Persist step of spec §4.2's third transition: any row of `model`
        still marked open whose last_seen predates this cycle was NOT
        re-observed this cycle (emit() would have advanced last_seen to
        cycle_time otherwise) -> close it. No in-memory "touched" set is
        needed; the watermark comparison on last_seen is sufficient and is a
        single indexed UPDATE (see the ix_*_open_last_seen partial index).

        Must be called once per table per cycle, after all of that table's
        collect(sink) calls for the cycle have run. Returns the number of
        rows closed."""
        result = self._session.execute(
            update(model)
            .where(model.still_present.is_(True), model.last_seen < cycle_time)
            .values(still_present=False)
            .execution_options(synchronize_session="fetch")
        )
        return result.rowcount
