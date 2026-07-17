"""Push-shaped auth-journal collector (spec §3, §6 rule 5, §12).

Reads journalctl in JSON mode for the identifiers auth-relevant tools log
under (sshd, sudo, login -- PAM-driven failures from any of these surface
under the same identifiers), parses each line's MESSAGE against known
sshd/PAM message formats, and emits one AuthEventObservation per
recognized event.

Message-format parsing is inherently best-effort against free-text log
lines: spec §5 calls this source "lossless" in the sense that journald's
own record-keeping is a complete history (nothing is sampled or dropped at
the collection-interval level, unlike process/network snapshots), not in
the sense that every line's meaning is perfectly extracted. Unrecognized
lines are skipped rather than guessed at.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timedelta, timezone

from sentry.engine.clock import Clock, SystemClock
from sentry.engine.observations import AuthEventObservation
from sentry.engine.sink import ObservationSink

DEFAULT_IDENTIFIERS: tuple[str, ...] = ("sshd", "sudo", "login")
DEFAULT_LOOKBACK = timedelta(minutes=15)  # generous overlap margin; event_key dedup makes re-processing safe

_SSHD_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)
_SSHD_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
_SSHD_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_PAM_AUTH_FAILURE_RE = re.compile(r"pam_unix\((?P<service>[^:]+):auth\): authentication failure;.*?user=(?P<user>\S+)")
_PAM_RHOST_RE = re.compile(r"rhost=(?P<ip>\S+)")
_SUDO_COMMAND_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*?\bCOMMAND=")


def _parse_message(identifier: str, message: str) -> tuple[str, str | None, str | None, str] | None:
    """Returns (service, account, source_ip, outcome) or None if the line
    doesn't match a known auth-event pattern."""
    m = _SSHD_ACCEPTED_RE.search(message)
    if m:
        return "sshd", m.group("user"), m.group("ip"), "success"

    m = _SSHD_FAILED_RE.search(message)
    if m:
        return "sshd", m.group("user"), m.group("ip"), "failure"

    m = _SSHD_INVALID_USER_RE.search(message)
    if m:
        return "sshd", m.group("user"), m.group("ip"), "failure"

    m = _PAM_AUTH_FAILURE_RE.search(message)
    if m:
        ip_match = _PAM_RHOST_RE.search(message)
        ip = ip_match.group("ip") if ip_match else None
        return m.group("service"), m.group("user"), ip, "failure"

    if identifier == "sudo" and "incorrect password attempt" not in message:
        m = _SUDO_COMMAND_RE.search(message)
        if m:
            return "sudo", m.group("user"), None, "success"

    return None


def _parse_realtime_timestamp(value: object) -> datetime | None:
    """journalctl JSON's __REALTIME_TIMESTAMP is microseconds since epoch,
    encoded as a string."""
    if value is None:
        return None
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)


class JournalAuthCollector:
    name = "journal_auth"
    respects_warmup = False  # rule 5 is live immediately per spec §7

    def __init__(
        self,
        identifiers: tuple[str, ...] = DEFAULT_IDENTIFIERS,
        lookback: timedelta = DEFAULT_LOOKBACK,
        clock: Clock = SystemClock(),
        journalctl_path: str = "journalctl",
    ):
        self._identifiers = identifiers
        self._lookback = lookback
        self._clock = clock
        self._journalctl_path = journalctl_path

    def collect(self, sink: ObservationSink) -> None:
        for record in self._read_journal_records():
            self._emit_from_record(sink, record)

    def _read_journal_records(self) -> list[dict]:
        since = (self._clock.now() - self._lookback).strftime("%Y-%m-%d %H:%M:%S")
        cmd = [self._journalctl_path, "-o", "json", "--since", since]
        for identifier in self._identifiers:
            cmd += ["-t", identifier]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return []  # degrade gracefully (spec §11) -- journalctl unavailable
        if result.returncode != 0:
            return []

        records = []
        for raw_line in result.stdout.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                records.append(json.loads(raw_line))
            except json.JSONDecodeError:
                continue
        return records

    def _emit_from_record(self, sink: ObservationSink, record: dict) -> None:
        message = record.get("MESSAGE")
        if not isinstance(message, str):
            return

        identifier = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or ""
        parsed = _parse_message(identifier, message)
        if parsed is None:
            return
        service, account, source_ip, outcome = parsed

        occurred_at = _parse_realtime_timestamp(record.get("__REALTIME_TIMESTAMP"))
        if occurred_at is None:
            return

        sink.emit(
            AuthEventObservation(
                occurred_at=occurred_at,
                service=service,
                account=account,
                source_ip=source_ip,
                outcome=outcome,
                raw_message=message,
            )
        )
