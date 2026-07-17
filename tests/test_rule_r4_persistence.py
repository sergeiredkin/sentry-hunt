from __future__ import annotations

from datetime import timedelta

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext
from sentry.rules.r4_persistence import PersistenceRule
from sentry.storage.models import PersistenceEntryRow
from tests.conftest import make_persistence_entry_observation


def test_fires_on_new_persistence_entry(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(mechanism="systemd_system", unit_or_path="/etc/systemd/system/evil.service"))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PersistenceRule().evaluate(ctx)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence["old_command"] is None
    assert "New persistence entry" in findings[0].title


def test_fires_on_command_change_with_before_after(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(command="/usr/bin/foo --daemon"))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(command="/usr/bin/foo --daemon --backdoor"))
    sink.close_cycle(PersistenceEntryRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PersistenceRule().evaluate(ctx)

    assert len(findings) == 1
    assert findings[0].evidence["old_command"] == "/usr/bin/foo --daemon"
    assert findings[0].evidence["command"] == "/usr/bin/foo --daemon --backdoor"
    assert "command changed" in findings[0].title


def test_no_finding_when_unchanged(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation())

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation())  # identical

    ctx = EvalContext(session, since=t1, until=t1 + timedelta(seconds=60))
    findings = PersistenceRule().evaluate(ctx)

    assert findings == []


def test_fires_for_each_mechanism_type(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_persistence_entry_observation(mechanism="cron", unit_or_path="/etc/cron.d/job1", command="/bin/a"))
    sink.emit(make_persistence_entry_observation(mechanism="autostart", unit_or_path="/home/alice/.config/autostart/x.desktop", command="/bin/b"))
    sink.emit(make_persistence_entry_observation(mechanism="shell_rc", unit_or_path="/home/alice/.bashrc", command="export X=1"))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PersistenceRule().evaluate(ctx)

    assert len(findings) == 3
    mechanisms = {f.evidence["mechanism"] for f in findings}
    assert mechanisms == {"cron", "autostart", "shell_rc"}
