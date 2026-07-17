from __future__ import annotations

import os
import threading
from datetime import timedelta

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext
from sentry.rules.r6_critical_change import CriticalChangeRule, _read_lines_best_effort
from sentry.storage.models import FileIntegrityRow
from tests.conftest import make_file_integrity_observation


def test_read_lines_best_effort_returns_none_for_fifo_without_hanging(tmp_path):
    fifo_path = tmp_path / "authorized_keys"
    os.mkfifo(fifo_path)

    result: dict[str, object] = {}

    def call():
        result["value"] = _read_lines_best_effort(str(fifo_path))

    t = threading.Thread(target=call, daemon=True)
    t.start()
    t.join(timeout=5)

    assert not t.is_alive(), "_read_lines_best_effort blocked on a FIFO instead of skipping it"
    assert result["value"] is None


def test_fires_on_hash_change_default_high_severity(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/ssh/sshd_config", sha256="a" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/ssh/sshd_config", sha256="b" * 64))
    sink.close_cycle(FileIntegrityRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = CriticalChangeRule().evaluate(ctx)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence["old_sha256"] == "a" * 64
    assert findings[0].evidence["new_sha256"] == "b" * 64
    assert "changed" in findings[0].title


def test_fires_on_new_authorized_keys_file_with_key_lines(session, fixed_clock, tmp_path):
    keys_file = tmp_path / "authorized_keys"
    keys_file.write_text("ssh-ed25519 AAAAattackerkey attacker@evil\n")

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path=str(keys_file)))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = CriticalChangeRule().evaluate(ctx)

    assert len(findings) == 1
    assert findings[0].evidence["old_sha256"] is None
    assert findings[0].evidence["current_authorized_keys"] == ["ssh-ed25519 AAAAattackerkey attacker@evil"]
    assert "appeared" in findings[0].title


def test_medium_severity_for_etc_hosts(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/hosts", sha256="a" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/hosts", sha256="b" * 64))
    sink.close_cycle(FileIntegrityRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = CriticalChangeRule().evaluate(ctx)

    assert findings[0].severity == "MEDIUM"


def test_binary_change_high_severity(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/usr/bin/su", sha256="a" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/usr/bin/su", sha256="b" * 64))
    sink.close_cycle(FileIntegrityRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = CriticalChangeRule().evaluate(ctx)

    assert findings[0].severity == "HIGH"


def test_excludes_sudoers_paths_owned_by_rule_2(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/sudoers"))
    sink.emit(make_file_integrity_observation(path="/etc/sudoers.d/90-cloud-init-users"))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = CriticalChangeRule().evaluate(ctx)

    assert findings == []


def test_fires_on_perms_change_evidence(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/passwd", perms_octal="644"))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/passwd", perms_octal="777"))
    sink.close_cycle(FileIntegrityRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = CriticalChangeRule().evaluate(ctx)

    assert findings[0].evidence["old_perms"] == "644"
    assert findings[0].evidence["new_perms"] == "777"


def test_no_finding_when_unchanged(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/passwd"))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/passwd"))  # identical

    ctx = EvalContext(session, since=t1, until=t1 + timedelta(seconds=60))
    findings = CriticalChangeRule().evaluate(ctx)

    assert findings == []
