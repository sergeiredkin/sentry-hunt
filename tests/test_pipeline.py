from __future__ import annotations

from sqlalchemy import select

from sentry.collectors._common import HashCache
from sentry.engine.pipeline import _write_alerts, run_cycle
from sentry.rules.r1_new_executable import NewExecutableRule
from sentry.storage.models import AlertRow, CollectorHealthRow, ProcessObservationRow
from tests.conftest import make_process_observation


class FakeCollector:
    name = "fake"
    respects_warmup = False

    def __init__(self, observations_by_call):
        self._observations_by_call = list(observations_by_call)
        self._call_index = 0

    def collect(self, sink):
        if self._call_index < len(self._observations_by_call):
            for obs in self._observations_by_call[self._call_index]:
                sink.emit(obs)
        self._call_index += 1


class RaisingCollector:
    name = "raising"
    respects_warmup = False

    def collect(self, sink):
        raise RuntimeError("simulated collector failure")


def test_first_cycle_persists_observations_and_returns_no_findings(session, tmp_path):
    collector = FakeCollector([[make_process_observation(exe_path="/usr/bin/bash", sha256="a" * 64)]])
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)

    cycle_time, findings = run_cycle(session, [collector], [NewExecutableRule(home=home)], previous_cycle_time=None)

    assert findings == []
    rows = session.execute(select(ProcessObservationRow)).scalars().all()
    assert len(rows) == 1
    assert session.execute(select(AlertRow)).scalars().all() == []


def test_second_cycle_evaluates_and_writes_alert(session, fixed_clock, tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    collector = FakeCollector(
        [
            [],  # cycle 1: empty baseline
            [make_process_observation(exe_path="/tmp/dropper", sha256="a" * 64)],  # cycle 2: new suspicious exe
        ]
    )
    rules = [NewExecutableRule(home=home)]

    t0, findings0 = run_cycle(session, [collector], rules, previous_cycle_time=None, clock=fixed_clock)
    assert findings0 == []

    from datetime import timedelta

    fixed_clock.advance(timedelta(seconds=60))
    t1, findings1 = run_cycle(session, [collector], rules, previous_cycle_time=t0, clock=fixed_clock)

    assert len(findings1) == 1
    assert findings1[0].severity == "MEDIUM"  # /tmp escalation

    alerts = session.execute(select(AlertRow)).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].rule_id == "R1"
    assert alerts[0].status == "active"
    assert alerts[0].dedup_key == findings1[0].dedup_key


def test_write_alerts_does_not_duplicate_same_dedup_key(session):
    from sentry.rules.base import Finding

    finding = Finding(rule_id="R1", severity="LOW", title="x", dedup_key="same-key", evidence={"a": 1})

    from datetime import datetime, timezone

    now = datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc)
    _write_alerts(session, [finding], now)
    _write_alerts(session, [finding], now)

    alerts = session.execute(select(AlertRow)).scalars().all()
    assert len(alerts) == 1


def test_evidence_json_round_trips(session):
    import json

    from datetime import datetime, timezone

    from sentry.rules.base import Finding

    finding = Finding(
        rule_id="R1", severity="LOW", title="x", dedup_key="k1", evidence={"exe_path": "/bin/x", "count": 3}
    )
    _write_alerts(session, [finding], datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc))

    alert = session.execute(select(AlertRow)).scalars().one()
    assert json.loads(alert.evidence_json) == {"exe_path": "/bin/x", "count": 3}


# --- security-review fixes: collector fault isolation, hash cache lifetime ---


def test_collector_health_records_success_and_failure(session):
    good = FakeCollector([[make_process_observation(exe_path="/bin/sh", sha256="c" * 64)]])
    bad = RaisingCollector()

    run_cycle(session, [good, bad], [], previous_cycle_time=None)

    rows = {row.collector_name: row for row in session.execute(select(CollectorHealthRow)).scalars()}
    assert rows["fake"].status == "ok"
    assert rows["fake"].observation_count == 1
    assert rows["raising"].status == "failed"
    assert "RuntimeError" in rows["raising"].error


def test_run_cycle_isolates_a_raising_collector(session, tmp_path):
    """A collector that raises must not prevent other collectors' data
    from being persisted, and must not propagate out of run_cycle()."""
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    good_collector = FakeCollector([[make_process_observation(exe_path="/usr/bin/bash", sha256="a" * 64)]])
    bad_collector = RaisingCollector()

    cycle_time, findings = run_cycle(
        session, [bad_collector, good_collector], [NewExecutableRule(home=home)], previous_cycle_time=None
    )

    assert findings == []
    rows = session.execute(select(ProcessObservationRow)).scalars().all()
    assert len(rows) == 1  # the good collector's observation still landed


def test_run_cycle_continues_and_commits_when_a_later_collector_raises(session, tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    good_collector = FakeCollector([[make_process_observation(exe_path="/usr/bin/bash", sha256="a" * 64)]])
    bad_collector = RaisingCollector()

    # good collector runs first this time -- its data must survive a
    # later collector blowing up in the same cycle.
    run_cycle(session, [good_collector, bad_collector], [], previous_cycle_time=None)

    rows = session.execute(select(ProcessObservationRow)).scalars().all()
    assert len(rows) == 1


def test_run_cycle_clears_hash_cache_at_start_of_every_call(session, tmp_path):
    hash_cache = HashCache()
    f = tmp_path / "bin"
    f.write_bytes(b"hello")
    hash_cache.get(str(f))
    assert hash_cache._cache  # sanity: something is cached

    run_cycle(session, [], [], previous_cycle_time=None, hash_cache=hash_cache)

    assert hash_cache._cache == {}  # cleared at the start of the cycle


def test_run_cycle_without_hash_cache_arg_still_works(session):
    # hash_cache is optional -- must not raise when omitted (default None).
    run_cycle(session, [], [], previous_cycle_time=None)
