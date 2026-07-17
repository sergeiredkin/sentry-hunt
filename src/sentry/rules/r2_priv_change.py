"""Rule 2 -- New sudo / privileged user or group change (spec §6).

Watches: users/groups inventory (membership of sudo/wheel, new UID-0
accounts) and file integrity on /etc/sudoers + /etc/sudoers.d/*.
Triggers: user added to sudo/wheel; new UID-0 account; change to any
sudoers file.
Severity: HIGH (always).
Source: inventory diff + file integrity on sudoers (lossless).
respects_warmup: False (live from minute one).
"""

from __future__ import annotations

from sentry.engine.identity import compute_identity_key
from sentry.rules.base import EvalContext, Finding
from sentry.storage.models import FileIntegrityRow, UserAccountRow


def _is_sudoers_path(path: str) -> bool:
    return path == "/etc/sudoers" or "/etc/sudoers.d/" in path


class PrivilegeChangeRule:
    id = "R2"
    default_severity = "HIGH"
    respects_warmup = False

    def evaluate(self, ctx: EvalContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._user_findings(ctx))
        findings.extend(self._sudoers_file_findings(ctx))
        return findings

    def _user_findings(self, ctx: EvalContext) -> list[Finding]:
        findings: list[Finding] = []
        diff = ctx.diff(UserAccountRow)

        for row in diff.new:
            if row.is_sudoer:
                findings.append(self._sudo_finding(row, before_groups=None))
            if row.uid == 0:
                findings.append(self._uid0_finding(row))

        for old, new in diff.changed:
            if new.is_sudoer and not old.is_sudoer:
                findings.append(self._sudo_finding(new, before_groups=old.groups_json))
            # uid is part of this table's logical key (username, uid), so a
            # uid change can never appear as a "changed" pair -- it always
            # shows up as gone(old uid) + new(new uid), already covered by
            # the diff.new loop above.

        return findings

    def _sudo_finding(self, row: UserAccountRow, before_groups: str | None) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=self.default_severity,
            title=f"User added to privileged group: {row.username}",
            dedup_key=compute_identity_key("finding:R2-sudo", row.username, row.uid),
            evidence={
                "username": row.username,
                "uid": row.uid,
                "gid": row.gid,
                "groups_before": before_groups,
                "groups_after": row.groups_json,
                "timestamp": row.last_seen.isoformat(),
            },
        )

    def _uid0_finding(self, row: UserAccountRow) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=self.default_severity,
            title=f"New UID-0 account: {row.username}",
            dedup_key=compute_identity_key("finding:R2-uid0", row.username, row.uid),
            evidence={
                "username": row.username,
                "uid": row.uid,
                "gid": row.gid,
                "groups": row.groups_json,
                "timestamp": row.first_seen.isoformat(),
            },
        )

    def _sudoers_file_findings(self, ctx: EvalContext) -> list[Finding]:
        findings: list[Finding] = []
        diff = ctx.diff(FileIntegrityRow)

        for row in diff.new:
            if _is_sudoers_path(row.path):
                findings.append(self._sudoers_finding(row, old=None))

        for old, new in diff.changed:
            if _is_sudoers_path(new.path):
                findings.append(self._sudoers_finding(new, old=old))

        return findings

    def _sudoers_finding(self, new: FileIntegrityRow, old: FileIntegrityRow | None) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=self.default_severity,
            title=f"Sudoers file changed: {new.path}",
            dedup_key=compute_identity_key("finding:R2-sudoers", new.path, new.sha256 or ""),
            evidence={
                "path": new.path,
                "old_sha256": old.sha256 if old else None,
                "new_sha256": new.sha256,
                "mtime": new.mtime.isoformat() if new.mtime else None,
            },
        )
