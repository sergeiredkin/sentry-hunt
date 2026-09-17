from datetime import timedelta

from sqlalchemy import select

from sentry.config.loader import AppConfig
from sentry.engine.pipeline import run_cycle
from sentry.rules.r1_new_executable import NewExecutableRule
from sentry.storage.models import AlertRow, AppStateRow
from tests.conftest import make_process_observation


class Collector:
    name = "test"
    respects_warmup = True

    def __init__(self, batches):
        self.batches = iter(batches)

    def collect(self, sink):
        for observation in next(self.batches, []):
            sink.emit(observation)


def test_warmup_stores_but_does_not_surface_noisy_rule(session, fixed_clock, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    collector = Collector([[], [make_process_observation(exe_path="/tmp/tool", sha256="a" * 64)]])
    config = AppConfig(warmup_days=7, skip_warmup=False)
    rules = [NewExecutableRule(home=home)]

    first, _ = run_cycle(session, [collector], rules, None, fixed_clock, config=config)
    fixed_clock.advance(timedelta(minutes=1))
    _, findings = run_cycle(session, [collector], rules, first, fixed_clock, config=config)

    assert findings == []
    alert = session.execute(select(AlertRow)).scalar_one()
    assert alert.status == "suppressed_warmup"


def test_last_cycle_state_resumes_after_restart(session, fixed_clock, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    collector = Collector([[], [make_process_observation(exe_path="/tmp/tool", sha256="b" * 64)]])
    config = AppConfig(skip_warmup=True)
    rules = [NewExecutableRule(home=home)]

    run_cycle(session, [collector], rules, None, fixed_clock, config=config)
    fixed_clock.advance(timedelta(minutes=1))
    _, findings = run_cycle(session, [collector], rules, None, fixed_clock, config=config)

    assert len(findings) == 1
    keys = {row.key for row in session.execute(select(AppStateRow)).scalars()}
    assert keys == {"warmup_started_at", "last_cycle_at"}
