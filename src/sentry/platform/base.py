"""Distro abstraction (spec §11): package manager, service enumeration, and
log layout differ across Debian/Ubuntu/Fedora/Rocky. Collectors call this
layer instead of hardcoding a command or path, so a name/path difference
between distros doesn't leak into collector logic.

Detection is probe-based (check what's actually present on this system)
rather than distro-name parsing (/etc/os-release branching) -- simpler and
correct even on distro variants/derivatives that don't match a hardcoded
name list.
"""

from __future__ import annotations

import grp
import subprocess
from functools import lru_cache
from pathlib import Path

_SUDO_GROUP_CANDIDATES = ("sudo", "wheel")
_SSH_SERVICE_CANDIDATES = ("ssh", "sshd")
_USER_CRONTAB_DIR_CANDIDATES = (
    Path("/var/spool/cron/crontabs"),  # Debian/Ubuntu
    Path("/var/spool/cron"),  # Fedora/RHEL/Rocky
)


class Platform:
    def sudo_group_names(self) -> list[str]:
        """Whichever of the known privileged-group names exist on this
        system. Debian/Ubuntu use 'sudo', Fedora/RHEL/Rocky use 'wheel';
        check both defensively since some systems configure both."""
        names = []
        for name in _SUDO_GROUP_CANDIDATES:
            try:
                grp.getgrnam(name)
                names.append(name)
            except KeyError:
                continue
        return names

    def ssh_service_units(self) -> list[str]:
        """Which systemd unit name(s) this system's SSH daemon uses ('ssh'
        on Debian/Ubuntu, 'sshd' on Fedora/RHEL/Rocky). Returns whichever
        candidate unit files are actually installed; empty if systemctl is
        unavailable or neither is installed (collectors must degrade
        gracefully rather than assume one name)."""
        installed = _installed_unit_names()
        if installed is None:
            return []
        return [name for name in _SSH_SERVICE_CANDIDATES if f"{name}.service" in installed]

    def user_crontab_dir(self) -> Path | None:
        """Directory holding per-user crontabs, or None if neither known
        location exists on this system."""
        for candidate in _USER_CRONTAB_DIR_CANDIDATES:
            if candidate.is_dir():
                return candidate
        return None


@lru_cache(maxsize=1)
def _installed_unit_names() -> frozenset[str] | None:
    try:
        result = subprocess.run(
            ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return frozenset(line.split()[0] for line in result.stdout.splitlines() if line.strip())
