from __future__ import annotations

from sqlalchemy import select

from sentry.engine.pipeline import _write_alerts, run_cycle
from sentry.rules.r1_new_executable import NewExecutableRule
from sentry.storage.models import AlertRow, ProcessObservationRow
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
