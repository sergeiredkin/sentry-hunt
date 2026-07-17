"""Rule 5 -- Failed-login spike / auth anomaly (spec §6).

Watches: journal auth facility (sshd, sudo, PAM, login) via auth_events.
Triggers: failed auth exceeds threshold in a window (default >5 failures
for one account, or >10 total, per 10 min -- both configurable), OR a
successful login from a never-before-seen source (new username, or new
remote IP, for that service).
Severity: MEDIUM; HIGH if a spike is immediately followed by a success for
one of the involved accounts (brute force that landed).
Source: journal (lossless).
respects_warmup: False.

Unlike the other five rules, this one does not use the interval diff engine
-- auth_events is append-only, not interval-shaped (see AuthEventRow's
docstring in storage/models.py). It queries a rolling lookback window
ending at ctx.until directly; the anomaly window (default 10 minutes) is
independent of ctx.since/until's own width (the collection cycle).
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from sentry.engine.identity import compute_identity_key
from sentry.rules.base import EvalContext, Finding
from sentry.storage.models import AuthEventRow

DEFAULT_PER_ACCOUNT_THRESHOLD = 5
DEFAULT_TOTAL_THRESHOLD = 10
DEFAULT_WINDOW = timedelta(minutes=10)


class AuthAnomalyRule:
    id = "R5"
    default_severity = "MEDIUM"
    respects_warmup = False

    def __init__(
        self,
        per_account_threshold: int = DEFAULT_PER_ACCOUNT_THRESHOLD,
        total_threshold: int = DEFAULT_TOTAL_THRESHOLD,
        window: timedelta = DEFAULT_WINDOW,
    ):
        self._per_account_threshold = per_account_threshold
        self._total_threshold = total_threshold
        self._window = window

    def evaluate(self, ctx: EvalContext) -> list[Finding]:
        window_start = ctx.until - self._window
        events = list(
            ctx.session.execute(
                select(AuthEventRow).where(
                    AuthEventRow.occurred_at > window_start,
                    AuthEventRow.occurred_at <= ctx.until,
                )
            ).scalars()
        )

        findings: list[Finding] = []
        spike = self._spike_finding(events, window_start, ctx.until)
        if spike is not None:
            findings.append(spike)
        findings.extend(self._new_source_findings(ctx.session, events))
        return findings

    def _spike_finding(self, events, window_start, window_end) -> Finding | None:
        failures = [e for e in events if e.outcome == "failure"]
        if not failures:
            return None

        by_account: dict[str, list] = {}
        for e in failures:
            by_account.setdefault(e.account or "unknown", []).append(e)

        spiking_accounts = {acct for acct, evts in by_account.items() if len(evts) > self._per_account_threshold}
        total_spike = len(failures) > self._total_threshold
        if not spiking_accounts and not total_spike:
            return None

        involved_accounts = set(spiking_accounts)
        if total_spike:
            involved_accounts |= set(by_account)

        last_failure_by_account = {acct: max(e.occurred_at for e in evts) for acct, evts in by_account.items()}
        successes = [e for e in events if e.outcome == "success"]
        succeeded = any(
            (s.account or "unknown") in involved_accounts
            and s.occurred_at >= last_failure_by_account[s.account or "unknown"]
            for s in successes
        )

        severity = "HIGH" if succeeded else self.default_severity
        source_ips = sorted({e.source_ip for e in failures if e.source_ip})
        services = sorted({e.service for e in failures})

        # Bucketed by hour so the same in-progress incident doesn't mint a
        # new dedup_key every evaluation cycle while it's still inside the
        # lookback window (spec §4.4: "so the same finding doesn't spam
        # every cycle") -- a fresh incident hours later still alerts.
        hour_bucket = window_end.replace(minute=0, second=0, microsecond=0).isoformat()

        return Finding(
            rule_id=self.id,
            severity=severity,
            title=f"Failed-login spike: {', '.join(sorted(involved_accounts))}",
            dedup_key=compute_identity_key("finding:R5-spike", ",".join(sorted(involved_accounts)), hour_bucket),
            evidence={
                "accounts": sorted(involved_accounts),
                "source_ips": source_ips,
                "failure_count": len(failures),
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "succeeded": succeeded,
                "service": services,
            },
        )

    def _new_source_findings(self, session, events) -> list[Finding]:
        findings = []
        for e in events:
            if e.outcome != "success":
                continue
            if self._is_first_success_from_source(session, e):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.default_severity,
                        title=f"Successful login from new source: {e.account}@{e.source_ip or 'local'}",
                        dedup_key=compute_identity_key(
                            "finding:R5-new-source", e.account or "", e.source_ip or "", e.service
                        ),
                        evidence={
                            "account": e.account,
                            "source_ip": e.source_ip,
                            "service": e.service,
                            "occurred_at": e.occurred_at.isoformat(),
                        },
                    )
                )
        return findings

    @staticmethod
    def _is_first_success_from_source(session, event: AuthEventRow) -> bool:
        prior_count = session.execute(
            select(func.count())
            .select_from(AuthEventRow)
            .where(
                AuthEventRow.outcome == "success",
                AuthEventRow.occurred_at < event.occurred_at,
                AuthEventRow.account == event.account,
                AuthEventRow.source_ip == event.source_ip,
                AuthEventRow.service == event.service,
            )
        ).scalar_one()
        return prior_count == 0
