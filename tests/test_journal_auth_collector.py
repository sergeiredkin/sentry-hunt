from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

from sqlalchemy import select

from sentry.collectors.journal_auth import JournalAuthCollector, _parse_message
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import AuthEventRow


class FakeSink:
    def __init__(self):
        self.emitted = []

    def emit(self, observation):
        self.emitted.append(observation)


class FakeCompletedProcess:
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


def _journal_line(
    message: str,
    identifier: str = "sshd",
    occurred_at: datetime = datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc),
) -> str:
    micros = int(occurred_at.timestamp() * 1_000_000)
    return json.dumps(
        {
            "MESSAGE": message,
            "SYSLOG_IDENTIFIER": identifier,
            "__REALTIME_TIMESTAMP": str(micros),
        }
    )


# --- _parse_message unit tests -------------------------------------------------


def test_parse_sshd_accepted_password():
    result = _parse_message("sshd", "Accepted password for alice from 203.0.113.5 port 51000 ssh2")
    assert result == ("sshd", "alice", "203.0.113.5", "success")


def test_parse_sshd_accepted_publickey():
    result = _parse_message("sshd", "Accepted publickey for bob from 198.51.100.9 port 22001 ssh2")
    assert result == ("sshd", "bob", "198.51.100.9", "success")


def test_parse_sshd_failed_password():
    result = _parse_message("sshd", "Failed password for root from 203.0.113.5 port 51000 ssh2")
    assert result == ("sshd", "root", "203.0.113.5", "failure")


def test_parse_sshd_failed_password_invalid_user():
    result = _parse_message("sshd", "Failed password for invalid user admin from 203.0.113.5 port 51000 ssh2")
    assert result == ("sshd", "admin", "203.0.113.5", "failure")


def test_parse_sshd_invalid_user_no_password_attempt():
    result = _parse_message("sshd", "Invalid user backdoor from 203.0.113.5 port 51000")
    assert result == ("sshd", "backdoor", "203.0.113.5", "failure")


def test_parse_pam_auth_failure_with_rhost():
    message = (
        "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 "
        "tty=/dev/pts/0 ruser= rhost=192.168.1.50  user=alice"
    )
    result = _parse_message("sudo", message)
    assert result == ("sudo", "alice", "192.168.1.50", "failure")


def test_parse_pam_auth_failure_without_rhost():
    message = (
        "pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 "
        "tty=tty1 ruser= rhost=  user=bob"
    )
    result = _parse_message("login", message)
    assert result == ("login", "bob", None, "failure")


def test_parse_sudo_successful_command():
    message = "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls /etc"
    result = _parse_message("sudo", message)
    assert result == ("sudo", "alice", None, "success")


def test_parse_sudo_incorrect_password_summary_line_not_double_counted():
    message = "alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
    result = _parse_message("sudo", message)
    assert result is None  # the earlier pam_unix failure line(s) already captured this


def test_parse_unrecognized_message_returns_none():
    result = _parse_message("sshd", "Server listening on 0.0.0.0 port 22.")
    assert result is None


# --- JournalAuthCollector.collect() ---------------------------------------------


def test_collect_emits_recognized_events(monkeypatch):
    stdout = "\n".join(
        [
            _journal_line("Accepted password for alice from 203.0.113.5 port 51000 ssh2"),
            _journal_line("Server listening on 0.0.0.0 port 22."),  # unrecognized, skipped
        ]
    )
    monkeypatch.setattr(
        "sentry.collectors.journal_auth.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(stdout=stdout),
    )

    sink = FakeSink()
    JournalAuthCollector().collect(sink)

    assert len(sink.emitted) == 1
    assert sink.emitted[0].account == "alice"
    assert sink.emitted[0].outcome == "success"


def test_collect_skips_malformed_json_lines(monkeypatch):
    stdout = "\n".join(["not valid json", _journal_line("Failed password for root from 1.2.3.4 port 22 ssh2")])
    monkeypatch.setattr(
        "sentry.collectors.journal_auth.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(stdout=stdout),
    )

    sink = FakeSink()
    JournalAuthCollector().collect(sink)

    assert len(sink.emitted) == 1
    assert sink.emitted[0].outcome == "failure"


def test_collect_skips_record_with_non_string_message(monkeypatch):
    stdout = json.dumps({"MESSAGE": {"nested": "object"}, "__REALTIME_TIMESTAMP": "1700000000000000"})
    monkeypatch.setattr(
        "sentry.collectors.journal_auth.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(stdout=stdout),
    )

    sink = FakeSink()
    JournalAuthCollector().collect(sink)

    assert len(sink.emitted) == 0


def test_collect_degrades_gracefully_when_journalctl_missing(monkeypatch):
    def raise_missing(*a, **k):
        raise FileNotFoundError("journalctl not found")

    monkeypatch.setattr("sentry.collectors.journal_auth.subprocess.run", raise_missing)

    sink = FakeSink()
    JournalAuthCollector().collect(sink)  # must not raise

    assert len(sink.emitted) == 0


def test_collect_degrades_gracefully_on_nonzero_returncode(monkeypatch):
    monkeypatch.setattr(
        "sentry.collectors.journal_auth.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(stdout="", returncode=1),
    )

    sink = FakeSink()
    JournalAuthCollector().collect(sink)

    assert len(sink.emitted) == 0


def test_collect_passes_since_and_identifiers_to_journalctl(monkeypatch, fixed_clock):
    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        return FakeCompletedProcess(stdout="")

    monkeypatch.setattr("sentry.collectors.journal_auth.subprocess.run", fake_run)

    JournalAuthCollector(identifiers=("sshd", "sudo"), clock=fixed_clock).collect(FakeSink())

    cmd = captured_cmd["cmd"]
    assert cmd[0] == "journalctl"
    assert "--since" in cmd
    assert cmd.count("-t") == 2
    assert "sshd" in cmd
    assert "sudo" in cmd


def test_collect_drives_sink_correctly_end_to_end(monkeypatch, session, fixed_clock):
    stdout = _journal_line(
        "Failed password for root from 203.0.113.5 port 51000 ssh2",
        occurred_at=datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(
        "sentry.collectors.journal_auth.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(stdout=stdout),
    )

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    JournalAuthCollector().collect(sink)

    rows = session.execute(select(AuthEventRow)).scalars().all()
    assert len(rows) == 1
    assert rows[0].service == "sshd"
    assert rows[0].outcome == "failure"
    assert rows[0].account == "root"


def test_collect_twice_with_same_log_line_does_not_duplicate(monkeypatch, session, fixed_clock):
    """Simulates journalctl --since windows overlapping between cycles."""
    stdout = _journal_line("Failed password for root from 203.0.113.5 port 51000 ssh2")
    monkeypatch.setattr(
        "sentry.collectors.journal_auth.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(stdout=stdout),
    )

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    collector = JournalAuthCollector()
    collector.collect(sink)
    collector.collect(sink)  # same window re-queried

    rows = session.execute(select(AuthEventRow)).scalars().all()
    assert len(rows) == 1
