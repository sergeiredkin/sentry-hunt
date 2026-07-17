"""Push-shaped file-integrity collector (spec §3, §6 rule 6, §12).

Watches a narrow, fixed list of critical files and binaries -- NOT a
recursive directory scan (general directory scanning is explicitly out of
scope for MVP, spec §1). Each collect() call re-stats and re-hashes every
path in the list and emits one FileIntegrityObservation per path that
currently exists.
"""

from __future__ import annotations

import pwd
import stat
from datetime import datetime, timezone
from pathlib import Path

from sentry.collectors._common import hash_file
from sentry.engine.observations import FileIntegrityObservation
from sentry.engine.sink import ObservationSink

# Rule 6's narrow fixed file list (spec §6) -- NOT recursive. /etc/sudoers
# is here too even though it's rule 2's evidence source, not rule 6's --
# spec §6 rule 2 explicitly names "file integrity on sudoers" as a source,
# so it rides the same watched-file mechanism; which rule reacts to which
# path is a rule-engine concern (task 6), not a collector concern.
DEFAULT_CRITICAL_FILES: tuple[str, ...] = (
    "/etc/ssh/sshd_config",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
)

DEFAULT_SUDOERS_D_DIR = "/etc/sudoers.d"

# Resolved against the invoking user's home directory at collect time --
# this is a single-user tool (spec: no fleet/multi-host anything).
DEFAULT_HOME_RELATIVE_CRITICAL_FILES: tuple[str, ...] = (
    ".ssh/authorized_keys",
    ".ssh/config",
)

# Judgment-call binary list (spec §6: "list configurable"). Decided for this
# deployment as the auth/shell-core binaries most plausibly trojaned to
# gain or keep privileged access, or to hide persistence.
DEFAULT_CRITICAL_BINARIES: tuple[str, ...] = (
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/login",
    "/usr/sbin/useradd",
    "/usr/sbin/usermod",
    "/usr/bin/crontab",
    "/usr/bin/systemctl",
    "/usr/bin/chsh",
    "/usr/bin/chage",
)

DEFAULT_LOCAL_BIN_DIR = "/usr/local/bin"


def default_critical_paths(
    home: Path | None = None,
    local_bin_dir: Path | None = None,
    sudoers_d_dir: Path | None = None,
) -> tuple[str, ...]:
    """Builds the default watch list: the fixed files, the ~/.ssh files
    resolved against `home`, the named binaries, every file currently
    present under `local_bin_dir` (spec §6: "SHA-256 of key binaries in
    /usr/bin and /usr/local/bin" -- /usr/local/bin is globbed in full since
    it's normally empty or small on a workstation, unlike /usr/bin), and
    every file currently present under `sudoers_d_dir` (a *new* file
    appearing in sudoers.d is itself the signal rule 2 needs, so that
    directory must be enumerated fresh each cycle rather than fixed)."""
    home = home or Path.home()
    home_files = tuple(str(home / rel) for rel in DEFAULT_HOME_RELATIVE_CRITICAL_FILES)
    local_bin = local_bin_dir or Path(DEFAULT_LOCAL_BIN_DIR)
    local_bin_files = tuple(str(p) for p in sorted(local_bin.iterdir()) if p.is_file()) if local_bin.is_dir() else ()
    sudoers_d = sudoers_d_dir or Path(DEFAULT_SUDOERS_D_DIR)
    sudoers_d_files = tuple(str(p) for p in sorted(sudoers_d.iterdir()) if p.is_file()) if sudoers_d.is_dir() else ()
    return DEFAULT_CRITICAL_FILES + home_files + DEFAULT_CRITICAL_BINARIES + local_bin_files + sudoers_d_files


def _safe_username(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


class FileIntegrityCollector:
    name = "file_integrity"
    respects_warmup = False  # rule 6 is live immediately per spec §7

    def __init__(self, paths: tuple[str, ...] | None = None):
        # Exposed as a constructor param, not hardcoded in collect(), so
        # config wiring (task 11) can override the list without touching
        # collector logic.
        self._paths = paths if paths is not None else default_critical_paths()

    def collect(self, sink: ObservationSink) -> None:
        for path_str in self._paths:
            path = Path(path_str)
            try:
                st = path.stat()
            except OSError:
                continue  # doesn't exist / unreadable -- not observed this cycle

            sink.emit(
                FileIntegrityObservation(
                    path=path_str,
                    sha256=hash_file(path_str),  # None if unreadable (spec §11)
                    size_bytes=st.st_size,
                    owner=_safe_username(st.st_uid),
                    perms_octal=oct(stat.S_IMODE(st.st_mode))[2:].zfill(3),
                    mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                )
            )
