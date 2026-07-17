"""Rule 6 -- Changed critical config / system binary (spec §6).

Watches (narrow fixed list, NOT recursive): the file_integrity rows for
sshd_config, authorized_keys, ssh client config, passwd, shadow, hosts, and
the configured critical binaries. /etc/sudoers[.d] rides the same
file_integrity table but is rule 2's evidence source, not rule 6's --
excluded here so the same change isn't reported twice under two rule IDs.
Triggers: hash change on a watched file; a new SSH authorized-keys file
appearing; permission/owner change on a watched file.
Severity: HIGH for ssh/passwd/shadow and binary changes; MEDIUM for others
(in practice, everything except /etc/hosts).
Source: file-integrity diff (lossless).
respects_warmup: False.
"""

from __future__ import annotations

from sentry.engine.identity import compute_identity_key
from sentry.rules.base import EvalContext, Finding
from sentry.storage.models import FileIntegrityRow

# Owned by rule 2 instead -- excluded here to avoid double-reporting.
_EXCLUDED_PATH_MARKERS = ("/etc/sudoers",)

_MEDIUM_SEVERITY_PATHS = {"/etc/hosts"}


def _is_excluded(path: str) -> bool:
    return any(marker in path for marker in _EXCLUDED_PATH_MARKERS)


def _read_lines_best_effort(path: str) -> list[str] | None:
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return None


class CriticalChangeRule:
    id = "R6"
    default_severity = "HIGH"
    respects_warmup = False

    def evaluate(self, ctx: EvalContext) -> list[Finding]:
        diff = ctx.diff(FileIntegrityRow)
        findings: list[Finding] = []

        for row in diff.new:
            if _is_excluded(row.path):
                continue
            findings.append(self._finding(row, old=None))

        for old, new in diff.changed:
            if _is_excluded(new.path):
                continue
            findings.append(self._finding(new, old=old))

        return findings

    def _finding(self, new: FileIntegrityRow, old: FileIntegrityRow | None) -> Finding:
        evidence = {
            "path": new.path,
            "old_sha256": old.sha256 if old else None,
            "new_sha256": new.sha256,
            "old_perms": old.perms_octal if old else None,
            "new_perms": new.perms_octal,
            "old_owner": old.owner if old else None,
            "new_owner": new.owner,
            "mtime": new.mtime.isoformat() if new.mtime else None,
        }
        if new.path.endswith("authorized_keys"):
            # Only hashes are persisted, not raw content, so the exact
            # added/removed key line can't be diffed -- best-effort:
            # surface the file's current key lines instead.
            evidence["current_authorized_keys"] = _read_lines_best_effort(new.path)

        title = f"Critical file changed: {new.path}" if old is not None else f"Critical file appeared: {new.path}"
        return Finding(
            rule_id=self.id,
            severity=self._severity_for(new.path),
            title=title,
            dedup_key=compute_identity_key("finding:R6", new.path, new.sha256 or "", new.perms_octal or ""),
            evidence=evidence,
        )

    @staticmethod
    def _severity_for(path: str) -> str:
        if path in _MEDIUM_SEVERITY_PATHS:
            return "MEDIUM"
        return "HIGH"
