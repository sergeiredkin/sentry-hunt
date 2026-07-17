"""ingest -> persist -> diff -> evaluate -> alert (spec §2).

This is the minimal single-cycle version: run_cycle() drives every
collector into the sink, closes each interval table for the cycle, runs
the diff+rule engine over the (previous_cycle_time, this_cycle_time)
window, and writes resulting Findings as alerts (deduped by dedup_key
against still-active alerts).

Known gap, deliberately deferred (spec §13 task 7, not yet built): no
warmup or suppression wrapping here yet. Every rule's findings are written
as 'active' alerts regardless of `respects_warmup` -- rules 1 and 3 will be
noisy until warmup suppression exists. Continuous scheduling (APScheduler,
task 8) is also not wired here; a caller drives run_cycle() directly.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentry.collectors._common import HashCache
from sentry.collectors.base import Collector
from sentry.engine.clock import Clock, SystemClock
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext, Finding, Rule, run_rules
from sentry.storage.models import (
    AlertRow,
    FileIntegrityRow,
    NetworkObservationRow,
    PersistenceEntryRow,
    ProcessObservationRow,
    UserAccountRow,
)

# Every interval-shaped table a collector in the fixed MVP collector list
# (spec §6) writes to. auth_events (append-only) and system_inventory
# (point-in-time) are deliberately excluded -- close_cycle only applies to
# the interval model.
INTERVAL_MODELS = (
    ProcessObservationRow,
    NetworkObservationRow,
    UserAccountRow,
    PersistenceEntryRow,
    FileIntegrityRow,
)


def run_cycle(
    session: Session,
    collectors: Sequence[Collector],
    rules: Sequence[Rule],
    previous_cycle_time: datetime | None,
    clock: Clock = SystemClock(),
    hash_cache: HashCache | None = None,
) -> tuple[datetime, list[Finding]]:
    """Runs one full ingest->persist->diff->evaluate->alert cycle.

    `previous_cycle_time` is the timestamp of the last cycle the caller
    ran, or None on the very first run. On the first run, no diff/evaluate
    step happens at all -- there's no prior baseline to diff against, so
    every watched file/entry/process would otherwise show up as "new" and
    flood the very first cycle with alerts (the "day 0" problem). Returns
    this cycle's timestamp (pass it back in as `previous_cycle_time` next
    call) and the findings produced (empty on the first call).

    `hash_cache`, if given, is cleared at the start of every cycle. The
    cache (shared between ProcessCollector/NetworkCollector for
    performance -- see HashCache's docstring) must not outlive one cycle:
    rule 1's baseline check depends on the sha256 it reports being fresh,
    and clearing it here bounds any staleness to "within one snapshot
    interval" instead of "for the life of the process."
    """
    if hash_cache is not None:
        hash_cache.clear()

    sink = SqlAlchemyObservationSink(session, clock=clock)
    cycle_time = sink.begin_cycle()

    for collector in collectors:
        try:
            collector.collect(sink)
        except Exception:
            # One misbehaving collector (a permission edge case, a psutil
            # quirk, anything unanticipated) must not blind every other
            # collector for the cycle -- mirrors run_rules()'s per-rule
            # isolation in rules/base.py.
            import logging

            logging.getLogger(__name__).exception(
                "collector %s raised during collect()", getattr(collector, "name", collector)
            )

    for model in INTERVAL_MODELS:
        sink.close_cycle(model, cycle_time)
    session.commit()

    findings: list[Finding] = []
    if previous_cycle_time is not None:
        ctx = EvalContext(session, since=previous_cycle_time, until=cycle_time)
        findings = run_rules(list(rules), ctx)
        _write_alerts(session, findings, cycle_time)
        session.commit()

    return cycle_time, findings


def _write_alerts(session: Session, findings: list[Finding], created_at: datetime) -> None:
    for finding in findings:
        existing = session.execute(
            select(AlertRow).where(AlertRow.dedup_key == finding.dedup_key, AlertRow.status == "active")
        ).scalar_one_or_none()
        if existing is not None:
            continue  # already an active alert for this exact finding -- don't spam a duplicate row
        session.add(
            AlertRow(
                rule_id=finding.rule_id,
                severity=finding.severity,
                created_at=created_at,
                status="active",
                title=finding.title,
                evidence_json=json.dumps(finding.evidence, default=str),
                dedup_key=finding.dedup_key,
            )
        )
