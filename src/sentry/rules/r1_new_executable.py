"""Rule 1 -- New executable observed (spec §6).

Watches: process observations.
Triggers: an (exe_path, sha256) pair whose first_seen is in this window
and which has never appeared in baseline history (i.e. no row sharing that
pair -- open or closed -- with first_seen at or before the window start).
Severity: LOW by default; MEDIUM if exe_path is under ~/Downloads, /tmp,
/dev/shm, or /var/tmp.
Source: process snapshots (sampled).
respects_warmup: True (noisy -- every pip/npm/compiler/pkg-update trips it).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, select

from sentry.engine.identity import compute_identity_key
from sentry.rules.base import EvalContext, Finding
from sentry.storage.models import NetworkObservationRow, ProcessObservationRow

_SUSPICIOUS_PATH_PREFIXES = ("/tmp", "/dev/shm", "/var/tmp")


class NewExecutableRule:
    id = "R1"
    default_severity = "LOW"
    respects_warmup = True

    def __init__(self, home: Path | None = None):
        self._downloads_dir = str((home or Path.home()) / "Downloads")

    def evaluate(self, ctx: EvalContext) -> list[Finding]:
        diff = ctx.diff(ProcessObservationRow)
        candidates = list(diff.new) + [new for _old, new in diff.changed]

        findings: list[Finding] = []
        seen_pairs: set[tuple[str, str | None]] = set()  # avoid duplicate findings within one cycle

        for row in candidates:
            if row.exe_path is None:
                continue
            pair = (row.exe_path, row.sha256)
            if pair in seen_pairs:
                continue
            if self._seen_before(ctx.session, row.exe_path, row.sha256, ctx.since):
                continue
            seen_pairs.add(pair)

            severity = self._severity_for(row.exe_path)
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=severity,
                    title=f"New executable observed: {row.exe_path}",
                    dedup_key=compute_identity_key("finding:R1", row.exe_path, row.sha256 or ""),
                    evidence={
                        "exe_path": row.exe_path,
                        "sha256": row.sha256,
                        "cmdline": row.cmdline,
                        "ppid": row.ppid,
                        "parent_exe": self._parent_exe(ctx.session, row.ppid),
                        "user": row.user,
                        "first_seen": row.first_seen.isoformat(),
                        "concurrent_network_connections": self._concurrent_connections(ctx.session, row.pid),
                    },
                )
            )
        return findings

    def _severity_for(self, exe_path: str) -> str:
        if exe_path.startswith(self._downloads_dir):
            return "MEDIUM"
        if any(exe_path.startswith(prefix) for prefix in _SUSPICIOUS_PATH_PREFIXES):
            return "MEDIUM"
        return self.default_severity

    @staticmethod
    def _seen_before(session, exe_path: str, sha256: str | None, since) -> bool:
        """Aggregates over ALL rows (open or closed) sharing this
        (exe_path, sha256) pair, per the accepted ppid-reparent-churn note
        in engine/observations.py -- a single row's own first_seen isn't
        reliable since reparenting can close+reopen a row for the same
        underlying process."""
        earliest = session.execute(
            select(func.min(ProcessObservationRow.first_seen)).where(
                ProcessObservationRow.exe_path == exe_path,
                ProcessObservationRow.sha256 == sha256,
            )
        ).scalar_one_or_none()
        # <= since: a row first observed exactly at the window's start
        # boundary belongs to the *previous* window (see diff.py's window
        # convention) and so counts as prior baseline history here.
        return earliest is not None and earliest <= since

    @staticmethod
    def _parent_exe(session, ppid: int) -> str | None:
        return session.execute(
            select(ProcessObservationRow.exe_path).where(
                ProcessObservationRow.pid == ppid, ProcessObservationRow.still_present.is_(True)
            )
        ).scalars().first()

    @staticmethod
    def _concurrent_connections(session, pid: int | None) -> list[dict]:
        if pid is None:
            return []
        rows = session.execute(
            select(NetworkObservationRow).where(
                NetworkObservationRow.pid == pid, NetworkObservationRow.still_present.is_(True)
            )
        ).scalars().all()
        return [{"raddr": r.raddr, "rport": r.rport, "status": r.status} for r in rows]
