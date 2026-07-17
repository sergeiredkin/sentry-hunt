from __future__ import annotations

import hashlib


def compute_identity_key(kind: str, *parts: object) -> str:
    """Deterministic sha256 identity key.

    `kind` is a fixed literal per observation type ("process", "network",
    ...) so identity_keys are never ambiguous even if compared across
    tables. Every part that should make a changed entity count as a *new*
    interval must be included -- see the per-table identity/mutable field
    lists in observations.py and storage/models.py.
    """
    canonical = "|".join([kind, *(str(p) for p in parts)])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
