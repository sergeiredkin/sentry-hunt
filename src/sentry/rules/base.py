"""Rule protocol, EvalContext, Finding, and the rule-running orchestrator
(spec §6, §13 task 6).

Each rule is an independent, testable unit (spec §1's "Modular" principle):
evaluate() takes an EvalContext and returns a list of Findings, with no
side effects and no knowledge of warmup or suppression -- those wrap around
rule output at task 7, not inside the rule itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy.orm import Session

from sentry.engine.diff import DiffResult, diff_table
from sentry.storage.models import Base


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str  # LOW | MEDIUM | HIGH
    title: str
    dedup_key: str
    evidence: dict[str, Any]


class EvalContext:
    """What a rule sees: the diff window boundaries, a diff() helper memoized
    per (model, logical_key_fields) so multiple rules reading the same
    table's diff in one evaluation cycle don't re-run the query, and the
    session for any additional baseline-history queries a rule needs."""

    def __init__(self, session: Session, since: datetime, until: datetime):
        self.session = session
        self.since = since
        self.until = until
        self._diff_cache: dict[tuple, DiffResult] = {}

    def diff(self, model: type[Base], logical_key_fields: tuple[str, ...] | None = None) -> DiffResult:
        cache_key = (model, logical_key_fields)
        if cache_key not in self._diff_cache:
            self._diff_cache[cache_key] = diff_table(self.session, model, self.since, self.until, logical_key_fields)
        return self._diff_cache[cache_key]


class Rule(Protocol):
    id: str
    default_severity: str
    respects_warmup: bool

    def evaluate(self, ctx: EvalContext) -> list[Finding]: ...


def run_rules(rules: list[Rule], ctx: EvalContext) -> list[Finding]:
    """Runs every rule against the same context and concatenates findings.
    One rule raising must not prevent the others from running or crash the
    evaluate pipeline stage -- a bug in rule 6 shouldn't blind rule 2."""
    findings: list[Finding] = []
    for rule in rules:
        try:
            findings.extend(rule.evaluate(ctx))
        except Exception:
            import logging

            logging.getLogger(__name__).exception("rule %s raised during evaluate()", getattr(rule, "id", rule))
    return findings
