from __future__ import annotations

from datetime import timedelta

from sentry.engine.diff import diff_table
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import (
    FileIntegrityRow,
    NetworkObservationRow,
    ProcessObservationRow,
)
from tests.conftest import (
    make_file_integrity_observation,
    make_network_observation,
    make_process_observation,
)


def test_diff_reports_new_row_inserted_this_window(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100))

    result = diff_table(session, ProcessObservationRow, since=t0, until=t1)
    assert len(result.new) == 1
    assert result.new[0].pid == 100
    assert result.gone == []
    assert result.changed == []


def test_diff_reports_gone_row_closed_this_window(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.close_cycle(ProcessObservationRow, t1)  # not re-observed -> closes

    result = diff_table(session, ProcessObservationRow, since=t0, until=t1)
    assert len(result.gone) == 1
    assert result.gone[0].pid == 100
    assert result.new == []
    assert result.changed == []


def test_diff_pairs_file_integrity_hash_change_as_changed(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/passwd", sha256="a" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/passwd", sha256="b" * 64))
    sink.close_cycle(FileIntegrityRow, t1)

    result = diff_table(session, FileIntegrityRow, since=t0, until=t1)
    assert result.new == []
    assert result.gone == []
    assert len(result.changed) == 1
    old_row, new_row = result.changed[0]
    assert old_row.sha256 == "a" * 64
    assert new_row.sha256 == "b" * 64


def test_diff_network_owner_pid_change_reported_as_changed(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, pid=100))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, pid=200))
    sink.close_cycle(NetworkObservationRow, t1)

    result = diff_table(session, NetworkObservationRow, since=t0, until=t1)
    assert result.new == []
    assert result.gone == []
    assert len(result.changed) == 1
    old_row, new_row = result.changed[0]
    assert old_row.pid == 100
    assert new_row.pid == 200


def test_diff_unrelated_new_and_gone_not_paired(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/passwd"))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/hosts"))  # unrelated new path
    sink.close_cycle(FileIntegrityRow, t1)  # closes /etc/passwd via absence

    result = diff_table(session, FileIntegrityRow, since=t0, until=t1)
    assert len(result.new) == 1
    assert result.new[0].path == "/etc/hosts"
    assert len(result.gone) == 1
    assert result.gone[0].path == "/etc/passwd"
    assert result.changed == []


def test_diff_window_excludes_events_outside_range(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100))  # inserted before the window we'll query

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100))  # still present, just refreshed

    fixed_clock.advance(timedelta(seconds=60))
    t2 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=200))  # new within the [t1, t2] window

    result = diff_table(session, ProcessObservationRow, since=t1, until=t2)
    assert len(result.new) == 1
    assert result.new[0].pid == 200  # pid=100's first_seen (t0) is outside (t1, t2]


def test_diff_pid_reuse_treated_as_gone_and_new_not_changed(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100, create_time=1000.0))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100, create_time=2000.0))  # reused pid, different process
    sink.close_cycle(ProcessObservationRow, t1)

    result = diff_table(session, ProcessObservationRow, since=t0, until=t1)
    assert result.changed == []  # logical key includes create_time -- must not pair
    assert len(result.new) == 1
    assert result.new[0].create_time == 2000.0
    assert len(result.gone) == 1
    assert result.gone[0].create_time == 1000.0


def test_diff_process_reparent_treated_as_changed(session, fixed_clock):
    """Same pid, same create_time, different ppid -- the accepted-churn case
    documented in engine/observations.py -- should pair as 'changed', not
    show up as an unrelated gone+new."""
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100, ppid=500, create_time=1000.0))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100, ppid=1, create_time=1000.0))  # reparented to init
    sink.close_cycle(ProcessObservationRow, t1)

    result = diff_table(session, ProcessObservationRow, since=t0, until=t1)
    assert len(result.changed) == 1
    old_row, new_row = result.changed[0]
    assert old_row.ppid == 500
    assert new_row.ppid == 1
    assert result.new == []
    assert result.gone == []


def test_diff_returns_empty_result_when_nothing_changed(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100))  # unchanged, still present

    result = diff_table(session, ProcessObservationRow, since=t1, until=t1 + timedelta(seconds=60))
    assert result.new == []
    assert result.gone == []
    assert result.changed == []


def test_diff_multiple_unrelated_new_rows_all_reported(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100))
    sink.emit(make_process_observation(pid=200))
    sink.emit(make_process_observation(pid=300))

    result = diff_table(session, ProcessObservationRow, since=t0, until=t1)
    assert len(result.new) == 3
    assert {r.pid for r in result.new} == {100, 200, 300}


def test_diff_uses_default_logical_key_registry_for_persistence(session, fixed_clock):
    from sentry.storage.models import PersistenceEntryRow
    from tests.conftest import make_persistence_entry_observation

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(command="/usr/bin/foo --daemon"))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(command="/usr/bin/foo --evil"))
    sink.close_cycle(PersistenceEntryRow, t1)

    result = diff_table(session, PersistenceEntryRow, since=t0, until=t1)  # no explicit logical_key_fields
    assert len(result.changed) == 1
    old_row, new_row = result.changed[0]
    assert old_row.command == "/usr/bin/foo --daemon"
    assert new_row.command == "/usr/bin/foo --evil"
