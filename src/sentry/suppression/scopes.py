"""Suppression scope matching for alert findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentry.rules.base import Finding
from sentry.storage.models import SuppressionRow


def path_hash_value(path: str, sha256: str | None) -> str:
    """Stable, unambiguous value used by the path_hash scope."""
    return json.dumps({"path": path, "sha256": sha256}, sort_keys=True, separators=(",", ":"))


def _evidence_pairs(evidence: dict[str, Any]) -> list[tuple[str | None, str | None]]:
    pairs = []
    if "exe_path" in evidence:
        pairs.append((evidence.get("exe_path"), evidence.get("sha256")))
    if "path" in evidence:
        pairs.append((evidence.get("path"), evidence.get("new_sha256", evidence.get("sha256"))))
    return pairs


def matches(suppression: SuppressionRow, finding: Finding) -> bool:
    if suppression.rule_id != finding.rule_id:
        return False
    if suppression.scope == "rule_global":
        return True
    if suppression.scope == "exact_event":
        return suppression.match_value == finding.dedup_key
    if suppression.scope == "path":
        return any(path == suppression.match_value for path, _ in _evidence_pairs(finding.evidence))
    if suppression.scope == "hash":
        hashes = {sha for _, sha in _evidence_pairs(finding.evidence) if sha}
        return suppression.match_value in hashes
    if suppression.scope == "path_hash":
        try:
            expected = json.loads(suppression.match_value)
        except (TypeError, json.JSONDecodeError):
            return False
        return any(
            path == expected.get("path") and sha == expected.get("sha256")
            for path, sha in _evidence_pairs(finding.evidence)
        )
    return False


def is_suppressed(session: Session, finding: Finding, now: datetime) -> bool:
    rows = session.execute(
        select(SuppressionRow).where(
            SuppressionRow.rule_id.in_([finding.rule_id, "*"]),
            (SuppressionRow.expires_at.is_(None) | (SuppressionRow.expires_at > now)),
        )
    ).scalars()
    return any(matches(row, finding) for row in rows)
