from __future__ import annotations

from datetime import timedelta

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext
from sentry.rules.r3_new_listener import NewListenerRule
from sentry.storage.models import NetworkObservationRow
from tests.conftest import make_network_observation


def test_fires_on_new_wildcard_listener_high_severity(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=4444, status="LISTEN", pid=100))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = NewListenerRule().evaluate(ctx)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence["previous_pid"] is None


def test_fires_on_new_loopback_listener_low_severity(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="127.0.0.1", lport=5432, status="LISTEN", pid=100))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = NewListenerRule().evaluate(ctx)

    assert findings[0].severity == "LOW"


def test_fires_on_new_lan_listener_medium_severity(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="192.168.1.50", lport=8080, status="LISTEN", pid=100))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = NewListenerRule().evaluate(ctx)

    assert findings[0].severity == "MEDIUM"


def test_ignores_established_connections(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(
        make_network_observation(
            protocol="tcp", laddr="192.168.1.5", lport=443, raddr="8.8.8.8", rport=51000, status="ESTABLISHED", pid=100
        )
    )

    ctx = EvalContext(session, since=t0, until=t1)
    findings = NewListenerRule().evaluate(ctx)

    assert findings == []


def test_fires_on_owner_change_with_previous_pid_evidence(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, status="LISTEN", pid=100))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, status="LISTEN", pid=999))
    sink.close_cycle(NetworkObservationRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = NewListenerRule().evaluate(ctx)

    assert len(findings) == 1
    assert "owner changed" in findings[0].title
    assert findings[0].evidence["previous_pid"] == 100
    assert findings[0].evidence["pid"] == 999


def test_no_finding_when_baseline_unchanged(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, status="LISTEN", pid=100))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_network_observation(protocol="tcp", laddr="0.0.0.0", lport=22, status="LISTEN", pid=100))  # unchanged

    ctx = EvalContext(session, since=t1, until=t1 + timedelta(seconds=60))
    findings = NewListenerRule().evaluate(ctx)

    assert findings == []
