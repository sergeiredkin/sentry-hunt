from __future__ import annotations

from datetime import timedelta

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext
from sentry.rules.r2_priv_change import PrivilegeChangeRule
from sentry.storage.models import FileIntegrityRow, UserAccountRow
from tests.conftest import make_file_integrity_observation, make_user_account_observation


def test_fires_when_new_account_created_already_sudoer(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_user_account_observation(username="mallory", uid=1500, groups=("mallory", "sudo"), is_sudoer=True))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    sudo_findings = [f for f in findings if "privileged group" in f.title]
    assert len(sudo_findings) == 1
    assert sudo_findings[0].severity == "HIGH"
    assert sudo_findings[0].evidence["username"] == "mallory"


def test_fires_when_existing_account_added_to_sudo_group(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_user_account_observation(username="bob", uid=1001, groups=("bob",), is_sudoer=False))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_user_account_observation(username="bob", uid=1001, groups=("bob", "sudo"), is_sudoer=True))
    sink.close_cycle(UserAccountRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    sudo_findings = [f for f in findings if "privileged group" in f.title]
    assert len(sudo_findings) == 1
    assert sudo_findings[0].evidence["groups_before"] is not None
    assert "sudo" not in sudo_findings[0].evidence["groups_before"]
    assert "sudo" in sudo_findings[0].evidence["groups_after"]


def test_no_finding_for_non_sudo_account_change(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_user_account_observation(username="bob", uid=1001, shell="/bin/bash", is_sudoer=False, groups=("bob",)))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_user_account_observation(username="bob", uid=1001, shell="/bin/zsh", is_sudoer=False, groups=("bob",)))
    sink.close_cycle(UserAccountRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    assert findings == []


def test_fires_for_new_uid0_account(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_user_account_observation(username="rootkit", uid=0, gid=0, groups=("rootkit",), is_sudoer=False))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    uid0_findings = [f for f in findings if "UID-0" in f.title]
    assert len(uid0_findings) == 1
    assert uid0_findings[0].severity == "HIGH"


def test_fires_for_new_sudoers_file(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/sudoers"))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    sudoers_findings = [f for f in findings if "Sudoers file changed" in f.title]
    assert len(sudoers_findings) == 1
    assert sudoers_findings[0].evidence["old_sha256"] is None


def test_fires_for_changed_sudoers_file_with_old_new_hash(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/sudoers", sha256="a" * 64))

    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/sudoers", sha256="b" * 64))
    sink.close_cycle(FileIntegrityRow, t1)

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    sudoers_findings = [f for f in findings if "Sudoers file changed" in f.title]
    assert len(sudoers_findings) == 1
    assert sudoers_findings[0].evidence["old_sha256"] == "a" * 64
    assert sudoers_findings[0].evidence["new_sha256"] == "b" * 64


def test_fires_for_new_file_in_sudoers_d(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/sudoers.d/90-cloud-init-users"))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    assert len([f for f in findings if "Sudoers file changed" in f.title]) == 1


def test_no_finding_for_unrelated_file_change(session, fixed_clock):
    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    t0 = sink.begin_cycle()
    fixed_clock.advance(timedelta(seconds=60))
    t1 = sink.begin_cycle()
    sink.emit(make_file_integrity_observation(path="/etc/hosts"))

    ctx = EvalContext(session, since=t0, until=t1)
    findings = PrivilegeChangeRule().evaluate(ctx)

    assert findings == []
