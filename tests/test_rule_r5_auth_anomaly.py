from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext
from sentry.rules.r5_auth_anomaly import AuthAnomalyRule
from tests.conftest import make_auth_event_observation

UNTIL = datetime(2026, 7, 16, 9, 30, 0, tzinfo=timezone.utc)


def _emit_failures(sink, account, count, service="sshd", source_ip="203.0.113.5", start=UNTIL - timedelta(minutes=5)):
    for i in range(count):
        sink.emit(
            make_auth_event_observation(
                occurred_at=start + timedelta(seconds=i),
                account=account,
                service=service,
                source_ip=source_ip,
                outcome="failure",
                raw_message=f"Failed password for {account} from {source_ip} port {50000 + i} ssh2",
            )
        )


def _ctx(session) -> EvalContext:
    since = UNTIL - timedelta(seconds=60)
    return EvalContext(session, since=since, until=UNTIL)


def test_no_finding_below_threshold(session):
    sink = SqlAlchemyObservationSink(session)
    _emit_failures(sink, "alice", count=3)

    findings = AuthAnomalyRule().evaluate(_ctx(session))
    assert findings == []


def test_fires_per_account_spike(session):
    sink = SqlAlchemyObservationSink(session)
    _emit_failures(sink, "root", count=6)

    findings = AuthAnomalyRule().evaluate(_ctx(session))
    spike = [f for f in findings if "spike" in f.title]
    assert len(spike) == 1
    assert spike[0].severity == "MEDIUM"
    assert spike[0].evidence["failure_count"] == 6
    assert spike[0].evidence["accounts"] == ["root"]


def test_fires_total_spike_across_multiple_accounts(session):
    sink = SqlAlchemyObservationSink(session)
    # 11 total failures, 3-4 per account -- each below the per-account
    # threshold of 5, but the total threshold of 10 is crossed.
    _emit_failures(sink, "alice", count=4, source_ip="203.0.113.1")
    _emit_failures(sink, "bob", count=4, source_ip="203.0.113.2")
    _emit_failures(sink, "carol", count=3, source_ip="203.0.113.3")

    findings = AuthAnomalyRule().evaluate(_ctx(session))
    spike = [f for f in findings if "spike" in f.title]
    assert len(spike) == 1
    assert spike[0].evidence["failure_count"] == 11
    assert set(spike[0].evidence["accounts"]) == {"alice", "bob", "carol"}


def test_escalates_to_high_when_spike_followed_by_success(session):
    sink = SqlAlchemyObservationSink(session)
    _emit_failures(sink, "root", count=6, start=UNTIL - timedelta(minutes=5))
    sink.emit(
        make_auth_event_observation(
            occurred_at=UNTIL - timedelta(seconds=1),
            account="root",
            service="sshd",
            source_ip="203.0.113.5",
            outcome="success",
            raw_message="Accepted password for root from 203.0.113.5 port 51099 ssh2",
        )
    )

    findings = AuthAnomalyRule().evaluate(_ctx(session))
    spike = [f for f in findings if "spike" in f.title][0]
    assert spike.severity == "HIGH"
    assert spike.evidence["succeeded"] is True


def test_stays_medium_when_success_precedes_the_failures(session):
    sink = SqlAlchemyObservationSink(session)
    sink.emit(
        make_auth_event_observation(
            occurred_at=UNTIL - timedelta(minutes=9),  # well before the failures
            account="root",
            service="sshd",
            source_ip="198.51.100.9",
            outcome="success",
            raw_message="Accepted password for root from 198.51.100.9 port 40000 ssh2",
        )
    )
    _emit_failures(sink, "root", count=6, start=UNTIL - timedelta(minutes=5))

    findings = AuthAnomalyRule().evaluate(_ctx(session))
    spike = [f for f in findings if "spike" in f.title][0]
    assert spike.severity == "MEDIUM"
    assert spike.evidence["succeeded"] is False


def test_new_source_finding_for_first_success(session):
    sink = SqlAlchemyObservationSink(session)
    sink.emit(
        make_auth_event_observation(
            occurred_at=UNTIL - timedelta(seconds=10),
            account="alice",
            service="sshd",
            source_ip="203.0.113.77",
            outcome="success",
            raw_message="Accepted password for alice from 203.0.113.77 port 41000 ssh2",
        )
    )

    findings = AuthAnomalyRule().evaluate(_ctx(session))
    new_source = [f for f in findings if "new source" in f.title]
    assert len(new_source) == 1
    assert new_source[0].evidence["account"] == "alice"


def test_no_new_source_finding_when_prior_success_exists_even_outside_window(session):
    sink = SqlAlchemyObservationSink(session)
    # prior success, well outside the 10-minute lookback window
    sink.emit(
        make_auth_event_observation(
            occurred_at=UNTIL - timedelta(days=3),
            account="alice",
            service="sshd",
            source_ip="203.0.113.77",
            outcome="success",
            raw_message="Accepted password for alice from 203.0.113.77 port 40001 ssh2",
        )
    )
    sink.emit(
        make_auth_event_observation(
            occurred_at=UNTIL - timedelta(seconds=10),
            account="alice",
            service="sshd",
            source_ip="203.0.113.77",
            outcome="success",
            raw_message="Accepted password for alice from 203.0.113.77 port 41000 ssh2",
        )
    )

    findings = AuthAnomalyRule().evaluate(_ctx(session))
    assert [f for f in findings if "new source" in f.title] == []


def test_dedup_key_stable_within_same_hour_bucket(session):
    sink = SqlAlchemyObservationSink(session)
    _emit_failures(sink, "root", count=6)

    f1 = AuthAnomalyRule().evaluate(_ctx(session))
    later_ctx = EvalContext(session, since=UNTIL, until=UNTIL + timedelta(minutes=2))
    f2 = AuthAnomalyRule().evaluate(later_ctx)

    spike1 = [f for f in f1 if "spike" in f.title][0]
    spike2 = [f for f in f2 if "spike" in f.title][0]
    assert spike1.dedup_key == spike2.dedup_key


def test_dedup_key_changes_in_next_hour_bucket(session):
    sink = SqlAlchemyObservationSink(session)
    _emit_failures(sink, "root", count=6, start=UNTIL - timedelta(minutes=5))

    f1 = AuthAnomalyRule().evaluate(_ctx(session))

    next_hour = UNTIL + timedelta(hours=1)
    _emit_failures(sink, "root", count=6, start=next_hour - timedelta(minutes=5))
    later_ctx = EvalContext(session, since=next_hour - timedelta(seconds=60), until=next_hour)
    f2 = AuthAnomalyRule().evaluate(later_ctx)

    spike1 = [f for f in f1 if "spike" in f.title][0]
    spike2 = [f for f in f2 if "spike" in f.title][0]
    assert spike1.dedup_key != spike2.dedup_key


def test_custom_thresholds_and_window(session):
    sink = SqlAlchemyObservationSink(session)
    _emit_failures(sink, "root", count=2)

    findings = AuthAnomalyRule(per_account_threshold=1).evaluate(_ctx(session))
    assert any("spike" in f.title for f in findings)
