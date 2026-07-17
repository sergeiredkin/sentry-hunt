from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import NetworkObservationRow, ProcessObservationRow
from tests.conftest import make_network_observation, make_process_observation


def _all_process_rows(session):
    return session.execute(select(ProcessObservationRow)).scalars().all()


def _all_network_rows(session):
    return session.execute(select(NetworkObservationRow)).scalars().all()


def test_emit_new_observation_inserts_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle_time = sink.begin_cycle()

    sink.emit(make_process_observation())

    rows = _all_process_rows(session)
    assert len(rows) == 1
    row = rows[0]
    assert row.first_seen == cycle_time
    assert row.last_seen == cycle_time
    assert row.still_present is True


def test_emit_matching_open_observation_updates_last_seen(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_process_observation(cmdline="bash"))

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.emit(make_process_observation(cmdline="bash -c ls"))

    rows = _all_process_rows(session)
    assert len(rows) == 1
    row = rows[0]
    assert row.first_seen == cycle1
    assert row.last_seen == cycle2
    assert row.cmdline == "bash -c ls"
    assert row.still_present is True


def test_not_observed_this_cycle_closes_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_process_observation())

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    # nothing emitted this cycle for this identity
    closed = sink.close_cycle(ProcessObservationRow, cycle2)

    rows = _all_process_rows(session)
    assert len(rows) == 1
    row = rows[0]
    assert row.still_present is False
    assert row.last_seen == cycle1  # frozen at its last real value, per spec
    assert closed == 1


def test_pid_reuse_produces_new_identity_and_closes_old(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100, create_time=1000.0))

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100, create_time=2000.0))
    sink.close_cycle(ProcessObservationRow, cycle2)

    rows = _all_process_rows(session)
    assert len(rows) == 2
    old_row = next(r for r in rows if r.create_time == 1000.0)
    new_row = next(r for r in rows if r.create_time == 2000.0)

    assert old_row.still_present is False
    assert old_row.last_seen == cycle1
    assert new_row.still_present is True
    assert new_row.first_seen == cycle2
    assert new_row.last_seen == cycle2
    assert old_row.identity_key != new_row.identity_key


def test_reappearance_after_close_opens_new_row_not_a_resurrection(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_process_observation())

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.close_cycle(ProcessObservationRow, cycle2)  # closes via absence

    fixed_clock.advance(timedelta(seconds=60))
    cycle3 = sink.begin_cycle()
    sink.emit(make_process_observation())  # identical identity fields again

    rows = _all_process_rows(session)
    assert len(rows) == 2
    closed_row = next(r for r in rows if r.still_present is False)
    open_row = next(r for r in rows if r.still_present is True)

    assert closed_row.first_seen == cycle1
    assert closed_row.last_seen == cycle1  # untouched by the reopen
    assert open_row.first_seen == cycle3
    assert open_row.last_seen == cycle3


def test_concurrent_emits_same_cycle_same_identity_collapse_to_one_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle_time = sink.begin_cycle()

    sink.emit(make_process_observation(cmdline="bash"))
    sink.emit(make_process_observation(cmdline="bash"))

    rows = _all_process_rows(session)
    assert len(rows) == 1
    row = rows[0]
    assert row.first_seen == cycle_time
    assert row.last_seen == cycle_time


def test_network_owner_pid_change_creates_new_identity(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, pid=100))

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, pid=200))
    sink.close_cycle(NetworkObservationRow, cycle2)

    rows = _all_network_rows(session)
    assert len(rows) == 2
    old_row = next(r for r in rows if r.pid == 100)
    new_row = next(r for r in rows if r.pid == 200)
    assert old_row.still_present is False
    assert new_row.still_present is True
    assert old_row.identity_key != new_row.identity_key


def test_close_cycle_scoped_to_one_table_only(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_process_observation())
    sink.emit(make_network_observation())

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.close_cycle(ProcessObservationRow, cycle2)

    process_row = _all_process_rows(session)[0]
    network_row = _all_network_rows(session)[0]
    assert process_row.still_present is False
    assert network_row.still_present is True  # untouched -- different table


def test_close_cycle_returns_number_closed(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=1))
    sink.emit(make_process_observation(pid=2))
    sink.emit(make_process_observation(pid=3))

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=1))  # only pid=1 re-observed

    closed = sink.close_cycle(ProcessObservationRow, cycle2)
    assert closed == 2


def test_utc_datetime_rejects_naive_datetime(session):
    from datetime import datetime

    from sqlalchemy.exc import StatementError

    from sentry.storage.models import ProcessObservationRow

    naive = datetime(2026, 7, 16, 10, 0, 0)  # no tzinfo
    row = ProcessObservationRow(
        pid=1,
        ppid=1,
        exe_path="/bin/sh",
        sha256=None,
        cmdline="",
        user=None,
        create_time=1.0,
        first_seen=naive,
        last_seen=naive,
        still_present=True,
        identity_key="x",
    )
    session.add(row)
    try:
        session.flush()
        assert False, "expected an error for naive datetime"
    except StatementError as exc:
        assert isinstance(exc.orig, ValueError)
        session.rollback()


def test_utc_datetime_normalizes_non_utc_aware(session):
    from datetime import datetime, timedelta, timezone

    from sentry.storage.models import ProcessObservationRow

    tz_plus5 = timezone(timedelta(hours=5))
    aware = datetime(2026, 7, 16, 15, 0, 0, tzinfo=tz_plus5)  # == 10:00 UTC

    row = ProcessObservationRow(
        pid=1,
        ppid=1,
        exe_path="/bin/sh",
        sha256=None,
        cmdline="",
        user=None,
        create_time=1.0,
        first_seen=aware,
        last_seen=aware,
        still_present=True,
        identity_key="y",
    )
    session.add(row)
    session.flush()
    session.expire(row)

    assert row.first_seen == datetime(2026, 7, 16, 10, 0, 0, tzinfo=timezone.utc)
    assert row.first_seen.tzinfo is not None
