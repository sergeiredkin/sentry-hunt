from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import (
    AuthEventRow,
    FileIntegrityRow,
    PersistenceEntryRow,
    UserAccountRow,
)
from tests.conftest import (
    make_auth_event_observation,
    make_file_integrity_observation,
    make_persistence_entry_observation,
    make_user_account_observation,
)


def test_user_account_group_change_opens_new_row_closes_old(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_user_account_observation(groups=("alice",), is_sudoer=False))

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.emit(make_user_account_observation(groups=("alice", "sudo"), is_sudoer=True))
    sink.close_cycle(UserAccountRow, cycle2)

    rows = session.execute(select(UserAccountRow)).scalars().all()
    assert len(rows) == 2
    old_row = next(r for r in rows if r.is_sudoer is False)
    new_row = next(r for r in rows if r.is_sudoer is True)
    assert old_row.still_present is False
    assert new_row.still_present is True
    assert old_row.identity_key != new_row.identity_key


def test_user_account_mutable_field_update_does_not_open_new_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    sink.begin_cycle()
    sink.emit(make_user_account_observation(shell="/bin/bash"))

    fixed_clock.advance(timedelta(seconds=60))
    sink.begin_cycle()
    sink.emit(make_user_account_observation(shell="/bin/zsh"))  # same groups/uid/username

    rows = session.execute(select(UserAccountRow)).scalars().all()
    assert len(rows) == 1
    assert rows[0].shell == "/bin/zsh"


def test_persistence_command_change_opens_new_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(command="/usr/bin/foo --daemon"))

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(command="/usr/bin/foo --daemon --evil-flag"))
    sink.close_cycle(PersistenceEntryRow, cycle2)

    rows = session.execute(select(PersistenceEntryRow)).scalars().all()
    assert len(rows) == 2
    old_row = next(r for r in rows if not r.still_present)
    new_row = next(r for r in rows if r.still_present)
    assert old_row.command == "/usr/bin/foo --daemon"
    assert new_row.command == "/usr/bin/foo --daemon --evil-flag"


def test_file_integrity_hash_change_opens_new_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(sha256="c" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    cycle2 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(sha256="d" * 64))
    sink.close_cycle(FileIntegrityRow, cycle2)

    rows = session.execute(select(FileIntegrityRow)).scalars().all()
    assert len(rows) == 2
    old_row = next(r for r in rows if not r.still_present)
    new_row = next(r for r in rows if r.still_present)
    assert old_row.sha256 == "c" * 64
    assert new_row.sha256 == "d" * 64


def test_file_integrity_perms_change_opens_new_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    sink.begin_cycle()
    sink.emit(make_file_integrity_observation(perms_octal="644"))

    fixed_clock.advance(timedelta(seconds=60))
    sink.begin_cycle()
    sink.emit(make_file_integrity_observation(perms_octal="777"))

    rows = session.execute(select(FileIntegrityRow)).scalars().all()
    assert len(rows) == 2


def test_emit_auth_event_inserts_row(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    sink.emit(make_auth_event_observation())

    rows = session.execute(select(AuthEventRow)).scalars().all()
    assert len(rows) == 1
    assert rows[0].service == "sshd"
    assert rows[0].outcome == "failure"


def test_emit_duplicate_auth_event_does_not_double_insert(session, fixed_clock):
    """journalctl's --since window can overlap between cycles; the same
    log line re-ingested must not create a second row."""
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    sink.emit(make_auth_event_observation())
    sink.emit(make_auth_event_observation())  # identical event, re-ingested

    rows = session.execute(select(AuthEventRow)).scalars().all()
    assert len(rows) == 1


def test_emit_distinct_auth_events_both_inserted(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    sink.emit(make_auth_event_observation(account="root"))
    sink.emit(make_auth_event_observation(account="bob"))

    rows = session.execute(select(AuthEventRow)).scalars().all()
    assert len(rows) == 2


def test_auth_event_has_no_interval_fields_touched_by_close_cycle(session, fixed_clock):
    """Sanity check that auth_events isn't accidentally interval-shaped --
    AuthEventRow has no still_present column, so close_cycle must never be
    called against it (this test documents the expectation)."""
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    sink.emit(make_auth_event_observation())
    assert not hasattr(AuthEventRow, "still_present")
