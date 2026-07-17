"""Rule 4 -- New persistence entry (spec §6).

Watches: systemd units (system + user), cron (all crontabs + /etc/cron.*),
systemd timers, ~/.config/autostart, shell rc files.
Triggers: a new unit/timer/cron/autostart entry appears, OR an existing
entry's command changes.
Severity: HIGH (persistence is the strongest single attacker signal).
Source: inventory + file-integrity diff (lossless).
respects_warmup: False.
"""

from __future__ import annotations

from sentry.engine.identity import compute_identity_key
from sentry.rules.base import EvalContext, Finding
from sentry.storage.models import PersistenceEntryRow


class PersistenceRule:
    id = "R4"
    default_severity = "HIGH"
    respects_warmup = False

    def evaluate(self, ctx: EvalContext) -> list[Finding]:
        diff = ctx.diff(PersistenceEntryRow)
        findings: list[Finding] = []

        for row in diff.new:
            findings.append(self._finding(row, old_command=None))

        for old, new in diff.changed:
            findings.append(self._finding(new, old_command=old.command))

        return findings

    def _finding(self, row: PersistenceEntryRow, old_command: str | None) -> Finding:
        title = (
            f"Persistence entry command changed: {row.mechanism} {row.unit_or_path}"
            if old_command is not None
            else f"New persistence entry: {row.mechanism} {row.unit_or_path}"
        )
        return Finding(
            rule_id=self.id,
            severity=self.default_severity,
            title=title,
            dedup_key=compute_identity_key("finding:R4", row.mechanism, row.unit_or_path, row.identity_key),
            evidence={
                "mechanism": row.mechanism,
                "unit_or_path": row.unit_or_path,
                "command": row.command,
                "old_command": old_command,
                "owner_user": row.owner_user,
                "enabled": row.enabled,
                "first_seen": row.first_seen.isoformat(),
            },
        )
