from datetime import timedelta

from sentry.rules.base import Finding
from sentry.storage.models import SuppressionRow
from sentry.suppression.scopes import is_suppressed, path_hash_value


def finding(**evidence):
    return Finding("R1", "MEDIUM", "new executable", "event-1", evidence)


def add(session, scope, value, expires_at=None):
    session.add(SuppressionRow(
        rule_id="R1", scope=scope, match_value=value,
        reason="test", created_at=NOW, expires_at=expires_at, created_by="user"
    ))
    session.commit()


from datetime import datetime, timezone
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_path_hash_matches_same_binary_but_not_replacement(session):
    add(session, "path_hash", path_hash_value("/tmp/tool", "a" * 64))
    assert is_suppressed(session, finding(exe_path="/tmp/tool", sha256="a" * 64), NOW)
    assert not is_suppressed(session, finding(exe_path="/tmp/tool", sha256="b" * 64), NOW)


def test_exact_event_path_and_hash_scopes(session):
    add(session, "exact_event", "event-1")
    assert is_suppressed(session, finding(exe_path="/x", sha256="c" * 64), NOW)


def test_expired_suppression_is_ignored(session):
    add(session, "rule_global", "", NOW - timedelta(seconds=1))
    assert not is_suppressed(session, finding(exe_path="/x", sha256="c" * 64), NOW)
