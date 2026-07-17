"""Rule 3 -- New listening port / service (spec §6).

Watches: network observations, LISTEN sockets only.
Triggers: a port enters LISTEN that wasn't in baseline, OR a known port
changes its owning process.
Severity: MEDIUM default; LOW if bound to loopback (127.0.0.1/::1); HIGH if
bound to 0.0.0.0/:: (any new or owner-changed wildcard-bound listener is,
by definition, unexpected relative to baseline).
Source: network snapshots (sampled).
respects_warmup: True.
"""

from __future__ import annotations

from sentry.engine.identity import compute_identity_key
from sentry.rules.base import EvalContext, Finding
from sentry.storage.models import NetworkObservationRow

_LOOPBACK_ADDRS = {"127.0.0.1", "::1"}
_WILDCARD_ADDRS = {"0.0.0.0", "::"}


class NewListenerRule:
    id = "R3"
    default_severity = "MEDIUM"
    respects_warmup = True

    def evaluate(self, ctx: EvalContext) -> list[Finding]:
        diff = ctx.diff(NetworkObservationRow)
        findings: list[Finding] = []

        for row in diff.new:
            if row.status != "LISTEN":
                continue
            findings.append(self._finding(row, previous_pid=None))

        for old, new in diff.changed:
            if new.status != "LISTEN":
                continue
            findings.append(self._finding(new, previous_pid=old.pid))

        return findings

    def _finding(self, row: NetworkObservationRow, previous_pid: int | None) -> Finding:
        title = (
            f"Listening port owner changed: {row.protocol}/{row.lport}"
            if previous_pid is not None
            else f"New listening port: {row.protocol}/{row.lport}"
        )
        return Finding(
            rule_id=self.id,
            severity=self._severity_for(row.laddr),
            title=title,
            dedup_key=compute_identity_key("finding:R3", row.protocol, row.laddr, row.lport, row.pid or -1),
            evidence={
                "protocol": row.protocol,
                "port": row.lport,
                "bind_address": row.laddr,
                "pid": row.pid,
                "previous_pid": previous_pid,
                "exe_path": row.exe_path,
                "sha256": row.sha256,
                "user": row.user,
                "first_seen": row.first_seen.isoformat(),
            },
        )

    @staticmethod
    def _severity_for(laddr: str) -> str:
        if laddr in _LOOPBACK_ADDRS:
            return "LOW"
        if laddr in _WILDCARD_ADDRS:
            return "HIGH"
        return "MEDIUM"
