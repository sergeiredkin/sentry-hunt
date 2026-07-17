"""Diff engine (spec §13 task 5): computes new / changed / gone entities
between two points in the interval model, for any interval-shaped table.

Operates over a (since, until] window rather than a specific "cycle"
object, so the same function serves snapshot mode (window = one collection
interval) and continuous mode (window = anything, later) -- spec §15's
cadence/mode-agnostic requirement: "Diff engine, rules, and TUI read only
the interval model and are cadence/mode agnostic."

Not applicable to auth_events (append-only, not interval-shaped -- rule 5
queries it directly for windowed counts) or system_inventory (point-in-time
snapshot; no MVP rule diffs it).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentry.storage.models import (
    Base,
    FileIntegrityRow,
    NetworkObservationRow,
    PackageRow,
    PersistenceEntryRow,
    ProcessObservationRow,
    UserAccountRow,
)

# The fields that identify "the same real-world entity" across an
# identity_key change -- always a strict subset of that table's full
# identity fields (see each Observation type's identity_key property in
# engine/observations.py for why a given field is or isn't included in
# identity). A newly-opened row and a freshly-closed row that share a
# logical key are reported as one "changed" entity instead of separate
# new + gone entries.
#
#   process:     (pid, create_time) -- excludes ppid/exe_path, so a
#                reparent or an in-place exec() is a "changed" process,
#                while PID reuse (different create_time) is correctly
#                gone+new, never paired.
#   network:     (protocol, laddr, lport) -- excludes pid, so a service
#                restart that rebinds the same port is "changed" (rule 3's
#                "known port changes its owning process").
#   user:        (username, uid) -- excludes the groups hash, so a group
#                membership change is "changed" (rule 2's before/after).
#   persistence: (mechanism, unit_or_path) -- excludes the command hash,
#                so an ExecStart/command edit is "changed" (rule 4).
#   file:        (path,) -- excludes sha256/owner/perms, so any of a hash,
#                owner, or permission change is "changed" (rule 6).
LOGICAL_KEY_FIELDS: dict[type[Base], tuple[str, ...]] = {
    ProcessObservationRow: ("pid", "create_time"),
    NetworkObservationRow: ("protocol", "laddr", "lport"),
    UserAccountRow: ("username", "uid"),
    PersistenceEntryRow: ("mechanism", "unit_or_path"),
    FileIntegrityRow: ("path",),
    PackageRow: ("name", "package_manager"),
}


@dataclass(frozen=True)
class DiffResult:
    new: list[Any] = field(default_factory=list)
    gone: list[Any] = field(default_factory=list)
    changed: list[tuple[Any, Any]] = field(default_factory=list)  # (old_row, new_row)


def diff_table(
    session: Session,
    model: type[Base],
    since: datetime,
    until: datetime,
    logical_key_fields: tuple[str, ...] | None = None,
) -> DiffResult:
    """Computes new/changed/gone for `model` over the window (since, until].

    new:     rows whose first_seen falls in (since, until] -- opened here.
    gone:    rows whose still_present is False and whose last_seen falls in
             [since, until) -- closed here, with no same-logical-key row
             opened in the same window. The bound is the mirror image of
             "new" on purpose: a row's last_seen freezes at the *previous*
             window's timestamp when it closes (per §4.2, close_cycle never
             touches last_seen), so a row closed in this window has
             last_seen == since, not == until. Using [since, until) here
             (vs. (since, until] for new) is what makes consecutive windows
             partition every row into exactly one bucket with no gaps and
             no double-counting.
    changed: a gone row and a new row sharing a logical key, paired
             together instead of reported as separate new+gone entries.

    `logical_key_fields` defaults to LOGICAL_KEY_FIELDS[model]; pass it
    explicitly to override for a one-off query.
    """
    if logical_key_fields is None:
        logical_key_fields = LOGICAL_KEY_FIELDS[model]

    new_rows = list(
        session.execute(select(model).where(model.first_seen > since, model.first_seen <= until)).scalars()
    )
    gone_rows = list(
        session.execute(
            select(model).where(
                model.still_present.is_(False),
                model.last_seen >= since,
                model.last_seen < until,
            )
        ).scalars()
    )

    def logical_key(row: Any) -> tuple:
        return tuple(getattr(row, f) for f in logical_key_fields)

    gone_by_key: dict[tuple, list[Any]] = {}
    for row in gone_rows:
        gone_by_key.setdefault(logical_key(row), []).append(row)

    consumed_count: dict[tuple, int] = {}
    changed: list[tuple[Any, Any]] = []
    remaining_new: list[Any] = []

    for new_row in new_rows:
        key = logical_key(new_row)
        candidates = gone_by_key.get(key, ())
        used = consumed_count.get(key, 0)
        if used < len(candidates):
            changed.append((candidates[used], new_row))
            consumed_count[key] = used + 1
        else:
            remaining_new.append(new_row)

    consumed_ids = {id(row) for key, count in consumed_count.items() for row in gone_by_key[key][:count]}
    remaining_gone = [row for row in gone_rows if id(row) not in consumed_ids]

    return DiffResult(new=remaining_new, gone=remaining_gone, changed=changed)
