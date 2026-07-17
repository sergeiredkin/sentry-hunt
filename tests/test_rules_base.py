from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sentry.rules.base import EvalContext, Finding, run_rules
from sentry.storage.models import ProcessObservationRow


def _ctx(session) -> EvalContext:
    since = datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc)
    until = since + timedelta(seconds=60)
    return EvalContext(session=session, since=since, until=until)


def test_eval_context_diff_memoizes_per_model(session):
    ctx = _ctx(session)
    with patch("sentry.rules.base.diff_table") as mock_diff:
        mock_diff.return_value = "sentinel"
        ctx.diff(ProcessObservationRow)
        ctx.diff(ProcessObservationRow)
    assert mock_diff.call_count == 1


def test_eval_context_diff_different_logical_key_fields_cached_separately(session):
    ctx = _ctx(session)
    with patch("sentry.rules.base.diff_table") as mock_diff:
        mock_diff.return_value = "sentinel"
        ctx.diff(ProcessObservationRow, logical_key_fields=("pid",))
        ctx.diff(ProcessObservationRow, logical_key_fields=("pid", "create_time"))
    assert mock_diff.call_count == 2


class _StubRule:
    def __init__(self, rule_id, findings=None, raises=False):
        self.id = rule_id
        self.default_severity = "LOW"
        self.respects_warmup = False
        self._findings = findings or []
        self._raises = raises

    def evaluate(self, ctx):
        if self._raises:
            raise RuntimeError("boom")
        return self._findings


def test_run_rules_concatenates_findings_from_multiple_rules(session):
    ctx = _ctx(session)
    f1 = Finding(rule_id="R1", severity="LOW", title="a", dedup_key="k1", evidence={})
    f2 = Finding(rule_id="R2", severity="HIGH", title="b", dedup_key="k2", evidence={})

    results = run_rules([_StubRule("R1", [f1]), _StubRule("R2", [f2])], ctx)
    assert results == [f1, f2]


def test_run_rules_continues_after_one_rule_raises(session):
    ctx = _ctx(session)
    f2 = Finding(rule_id="R2", severity="HIGH", title="b", dedup_key="k2", evidence={})

    results = run_rules([_StubRule("R1", raises=True), _StubRule("R2", [f2])], ctx)
    assert results == [f2]
