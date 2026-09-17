"""ingest -> persist -> diff -> evaluate -> alert."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentry.collectors._common import HashCache
from sentry.collectors.base import Collector
from sentry.config.loader import AppConfig
from sentry.engine.clock import Clock, SystemClock
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.rules.base import EvalContext, Finding, Rule, run_rules
from sentry.suppression.scopes import is_suppressed
from sentry.storage.models import (
    AlertRow,
    AppStateRow,
    CollectorHealthRow,
    FileIntegrityRow,
    NetworkObservationRow,
    PersistenceEntryRow,
    ProcessObservationRow,
    UserAccountRow,
)

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
    config: AppConfig | None = None,
) -> tuple[datetime, list[Finding]]:
    """Run one cycle and persist baseline timestamps across restarts.

    The CLI supplies AppConfig. Direct callers without config retain the
    historical no-warmup behavior, which keeps the low-level API convenient
    for tests and embedding applications.
    """
    if hash_cache is not None:
        hash_cache.clear()

    config = config or AppConfig(skip_warmup=True)
    persisted_last = _get_state_time(session, "last_cycle_at")
    effective_previous = previous_cycle_time or persisted_last
    warmup_started = _get_state_time(session, "warmup_started_at")

    sink = SqlAlchemyObservationSink(session, clock=clock)
    cycle_time = sink.begin_cycle()

    for collector in collectors:
        name = getattr(collector, "name", collector.__class__.__name__)
        started = clock.now()
        before = sink.emitted_count
        health = session.get(CollectorHealthRow, name)
        if health is None:
            health = CollectorHealthRow(
                collector_name=name,
                last_started=started,
                status="ok",
                observation_count=0,
            )
            session.add(health)
        else:
            health.last_started = started
        try:
            collector.collect(sink)
            health.last_completed = clock.now()
            health.status = "ok"
            health.error = None
        except Exception as exc:
            import logging
            health.status = "failed"
            health.error = f"{type(exc).__name__}: {exc}"[:2000]
            logging.getLogger(__name__).exception("collector %s raised during collect()", name)
        health.observation_count = sink.emitted_count - before
        session.flush()

    for model in INTERVAL_MODELS:
        sink.close_cycle(model, cycle_time)

    if warmup_started is None:
        warmup_started = cycle_time
        _set_state_time(session, "warmup_started_at", warmup_started)
    _set_state_time(session, "last_cycle_at", cycle_time)
    session.commit()

    findings: list[Finding] = []
    if effective_previous is not None:
        ctx = EvalContext(session, since=effective_previous, until=cycle_time)
        all_findings = run_rules(list(rules), ctx)
        warmup_active = (
            not config.skip_warmup
            and cycle_time < warmup_started + timedelta(days=config.warmup_days)
        )
        _write_alerts(
            session,
            all_findings,
            cycle_time,
            warmup_active=warmup_active,
            rules=rules,
        )
        session.commit()
        findings = [
            finding for finding in all_findings
            if not (warmup_active and _rule_respects_warmup(rules, finding.rule_id))
        ]

    return cycle_time, findings


def _get_state_time(session: Session, key: str) -> datetime | None:
    row = session.get(AppStateRow, key)
    return datetime.fromisoformat(row.value) if row is not None else None


def _set_state_time(session: Session, key: str, value: datetime) -> None:
    row = session.get(AppStateRow, key)
    if row is None:
        session.add(AppStateRow(key=key, value=value.isoformat()))
    else:
        row.value = value.isoformat()


def _rule_respects_warmup(rules: Sequence[Rule], rule_id: str) -> bool:
    return any(rule.id == rule_id and rule.respects_warmup for rule in rules)


def _write_alerts(
    session: Session,
    findings: list[Finding],
    created_at: datetime,
    warmup_active: bool = False,
    rules: Sequence[Rule] = (),
) -> None:
    for finding in findings:
        warmup_suppressed = warmup_active and _rule_respects_warmup(rules, finding.rule_id)
        if not warmup_suppressed and is_suppressed(session, finding, created_at):
            continue
        existing = session.execute(
            select(AlertRow).where(AlertRow.dedup_key == finding.dedup_key)
        ).scalar_one_or_none()
        if existing is not None:
            continue
        session.add(
            AlertRow(
                rule_id=finding.rule_id,
                severity=finding.severity,
                created_at=created_at,
                status="suppressed_warmup" if warmup_suppressed else "active",
                title=finding.title,
                evidence_json=json.dumps(finding.evidence, default=str),
                dedup_key=finding.dedup_key,
            )
        )
