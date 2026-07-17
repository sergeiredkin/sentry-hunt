"""Push-shaped users/groups collector (spec §3, §6 rule 2, §12).

Parses /etc/passwd and /etc/group directly (rather than via the `pwd`/`grp`
NSS modules) so the watched files are explicit, configurable, and easy to
point at fixture files in tests -- spec §14 requires no dependence on live
host state.

Sudoers *file* changes (spec §6 rule 2: "file integrity on sudoers") are a
file_integrity collector concern, not this one -- see
collectors/file_integrity.py's DEFAULT_CRITICAL_FILES, which includes
/etc/sudoers and enumerates /etc/sudoers.d/*.
"""

from __future__ import annotations

from collections import namedtuple

from sentry.engine.observations import UserAccountObservation
from sentry.engine.sink import ObservationSink
from sentry.platform.base import Platform

_PasswdEntry = namedtuple("_PasswdEntry", ["username", "uid", "gid", "home_dir", "shell"])
_GroupEntry = namedtuple("_GroupEntry", ["name", "gid", "members"])


def _parse_passwd_file(path: str) -> list[_PasswdEntry]:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 7:
                continue
            username, _passwd, uid, gid, _gecos, home_dir, shell = fields[:7]
            try:
                entries.append(_PasswdEntry(username, int(uid), int(gid), home_dir, shell))
            except ValueError:
                continue
    return entries


def _parse_group_file(path: str) -> dict[str, _GroupEntry]:
    groups: dict[str, _GroupEntry] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 4:
                continue
            name, _passwd, gid, members_field = fields[:4]
            members = tuple(m for m in members_field.split(",") if m)
            try:
                groups[name] = _GroupEntry(name, int(gid), members)
            except ValueError:
                continue
    return groups


def _build_membership_index(groups: dict[str, _GroupEntry]) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for group in groups.values():
        for member in group.members:
            index.setdefault(member, set()).add(group.name)
    return index


class UsersCollector:
    name = "users"
    respects_warmup = False  # rule 2 is live immediately per spec §7

    def __init__(
        self,
        passwd_path: str = "/etc/passwd",
        group_path: str = "/etc/group",
        sudo_group_names: tuple[str, ...] | None = None,
    ):
        self._passwd_path = passwd_path
        self._group_path = group_path
        # Injectable so tests don't depend on the live system's actual
        # sudo/wheel group configuration; defaults to the platform probe.
        self._sudo_group_names = (
            sudo_group_names if sudo_group_names is not None else tuple(Platform().sudo_group_names())
        )

    def collect(self, sink: ObservationSink) -> None:
        try:
            groups = _parse_group_file(self._group_path)
        except OSError:
            groups = {}

        try:
            passwd_entries = _parse_passwd_file(self._passwd_path)
        except OSError:
            return  # nothing readable this cycle -- degrade gracefully (spec §11)

        gid_to_group_name = {g.gid: g.name for g in groups.values()}
        supplementary_by_user = _build_membership_index(groups)
        sudo_names = set(self._sudo_group_names)

        for entry in passwd_entries:
            all_groups = set(supplementary_by_user.get(entry.username, set()))
            primary_group_name = gid_to_group_name.get(entry.gid)
            if primary_group_name:
                all_groups.add(primary_group_name)

            sink.emit(
                UserAccountObservation(
                    username=entry.username,
                    uid=entry.uid,
                    gid=entry.gid,
                    home_dir=entry.home_dir,
                    shell=entry.shell,
                    groups=tuple(sorted(all_groups)),
                    is_sudoer=bool(all_groups & sudo_names),
                )
            )
