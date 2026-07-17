from __future__ import annotations

from datetime import timedelta

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext
from sentry.rules.r1_new_executable import NewExecutableRule
from sentry.storage.models import NetworkObservationRow, ProcessObservationRow
from tests.conftest import make_network_observation, make_process_observation


def _rule(tmp_path) -> NewExecutableRule:
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    return NewExecutableRule(home=home)


def test_fires_on_new_executable(session, fixed_clock, tmp_path):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(exe_path="/usr/bin/newthing", sha256="a" * 64))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = _rule(tmp_path).evaluate(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "R1"
    assert findings[0].severity == "LOW"
    assert findings[0].evidence["exe_path"] == "/usr/bin/newthing"


def test_no_finding_when_pair_seen_before(session, fixed_clock, tmp_path):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=100, exe_path="/usr/bin/bash", sha256="a" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.close_cycle(ProcessObservationRow, t1)  # old pid closes

    fixed_clock.advance(timedelta(seconds=60))
    t2 = sink.begin_cycle()
    # same exe_path+sha256, but a different pid (process restarted) -> "new" row this window
    sink.emit(make_process_observation(pid=200, exe_path="/usr/bin/bash", sha256="a" * 64))

    ctx = EvalContext(session, since=t1, until=t2)
    findings = _rule(tmp_path).evaluate(ctx)

    assert findings == []  # (exe_path, sha256) pair already existed before this window


def test_escalates_to_medium_for_tmp_path(session, fixed_clock, tmp_path):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(exe_path="/tmp/dropper", sha256="a" * 64))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = _rule(tmp_path).evaluate(ctx)

    assert findings[0].severity == "MEDIUM"


def test_escalates_to_medium_for_downloads_path(session, fixed_clock, tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    downloads_exe = str(home / "Downloads" / "totally-safe.bin")

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(exe_path=downloads_exe, sha256="a" * 64))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = NewExecutableRule(home=home).evaluate(ctx)

    assert findings[0].severity == "MEDIUM"


def test_escalates_to_medium_for_dev_shm_and_var_tmp(session, fixed_clock, tmp_path):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=1, exe_path="/dev/shm/x", sha256="a" * 64))
    sink.emit(make_process_observation(pid=2, exe_path="/var/tmp/y", sha256="b" * 64))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = _rule(tmp_path).evaluate(ctx)

    assert all(f.severity == "MEDIUM" for f in findings)
    assert len(findings) == 2


def test_no_finding_for_row_without_exe_path(session, fixed_clock, tmp_path):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(exe_path=None, sha256=None))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = _rule(tmp_path).evaluate(ctx)

    assert findings == []


def test_evidence_includes_parent_exe_and_concurrent_connections(session, fixed_clock, tmp_path):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=1, ppid=0, exe_path="/usr/bin/parent", sha256="p" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=1, ppid=0, exe_path="/usr/bin/parent", sha256="p" * 64))  # keep parent open
    sink.emit(make_process_observation(pid=50, ppid=1, exe_path="/usr/bin/child", sha256="c" * 64))
    sink.emit(
        make_network_observation(
            protocol="tcp", laddr="0.0.0.0", lport=4444, pid=50, status="ESTABLISHED", raddr="1.2.3.4", rport=9999
        )
    )

    ctx = EvalContext(session, since=t0, until=t1)
    findings = _rule(tmp_path).evaluate(ctx)

    child_finding = next(f for f in findings if f.evidence["exe_path"] == "/usr/bin/child")
    assert child_finding.evidence["parent_exe"] == "/usr/bin/parent"
    assert len(child_finding.evidence["concurrent_network_connections"]) == 1
    assert child_finding.evidence["concurrent_network_connections"][0]["raddr"] == "1.2.3.4"


def test_dedup_within_cycle_for_multiple_pids_same_exe_sha(session, fixed_clock, tmp_path):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_process_observation(pid=10, exe_path="/tmp/x", sha256="a" * 64))
    sink.emit(make_process_observation(pid=11, exe_path="/tmp/x", sha256="a" * 64))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = _rule(tmp_path).evaluate(ctx)

    assert len(findings) == 1
