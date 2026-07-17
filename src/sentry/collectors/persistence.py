"""Push-shaped persistence collector (spec §3, §6 rule 4, §12).

Enumerates known persistence mechanisms -- systemd units (system + user),
systemd timers, cron (crontabs + /etc/cron.*), ~/.config/autostart, and
shell rc files -- and emits one PersistenceEntryObservation per entry
found. Listing a handful of canonical, well-known directories is not the
"general recursive directory scanning" the spec puts out of scope for MVP
(§1) -- that restriction is about file-integrity hashing of arbitrary
paths, not enumerating the fixed set of places persistence mechanisms live.

All source paths are constructor parameters, defaulting to the real system
locations, so tests point at fixture directories instead of depending on
live host state (spec §14).
"""

from __future__ import annotations

import pwd
from pathlib import Path

from sentry.engine.observations import PersistenceEntryObservation
from sentry.engine.sink import ObservationSink
from sentry.platform.base import Platform

DEFAULT_SYSTEM_UNIT_DIRS: tuple[Path, ...] = (
    Path("/etc/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
)
DEFAULT_USER_UNIT_DIR_RELATIVE = ".config/systemd/user"
DEFAULT_SYSTEM_CRONTAB = Path("/etc/crontab")
DEFAULT_CRON_D_DIR = Path("/etc/cron.d")
DEFAULT_CRON_PERIODIC_DIRS: tuple[Path, ...] = (
    Path("/etc/cron.hourly"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
)
DEFAULT_AUTOSTART_DIR_RELATIVE = ".config/autostart"
DEFAULT_SHELL_RC_FILES_RELATIVE: tuple[str, ...] = (".bashrc", ".profile", ".zshrc")


def _current_username() -> str | None:
    try:
        import os

        return pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, OSError):
        return None


def _read_text_or_none(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


def _parse_unit_exec_start(text: str) -> str | None:
    """Best-effort extraction of the command a .service unit runs. Manual
    line scan rather than configparser: systemd unit files permit repeated
    keys and syntax configparser doesn't model cleanly; last non-empty
    ExecStart= in [Service] wins, matching systemd's own override
    semantics closely enough for change-detection purposes."""
    exec_start: str | None = None
    in_service = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_service = line[1:-1].strip().lower() == "service"
            continue
        if in_service and line.startswith("ExecStart="):
            exec_start = line.partition("=")[2].strip()
    return exec_start


def _parse_timer_schedule(text: str) -> str | None:
    """Best-effort extraction of a .timer unit's schedule expression."""
    schedule: str | None = None
    in_timer = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_timer = line[1:-1].strip().lower() == "timer"
            continue
        if in_timer and line.startswith(("OnCalendar=", "OnBootSec=", "OnUnitActiveSec=", "OnStartupSec=")):
            schedule = line
    return schedule


def _parse_desktop_exec(text: str) -> tuple[str | None, bool]:
    """Returns (Exec= command, enabled) for a .desktop autostart entry."""
    exec_cmd: str | None = None
    enabled = True
    in_entry = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_entry = line[1:-1].strip() == "Desktop Entry"
            continue
        if not in_entry:
            continue
        if line.startswith("Exec="):
            exec_cmd = line.partition("=")[2].strip()
        elif line.startswith("Hidden=") and line.partition("=")[2].strip().lower() == "true":
            enabled = False
        elif (
            line.startswith("X-GNOME-Autostart-enabled=")
            and line.partition("=")[2].strip().lower() == "false"
        ):
            enabled = False
    return exec_cmd, enabled


def _is_env_assignment_line(line: str) -> bool:
    first_token = line.split(None, 1)[0] if line.split() else ""
    return "=" in first_token


def _parse_system_cron_lines(text: str) -> list[tuple[str, str]]:
    """System-style crontab lines: min hour dom month dow user command."""
    entries = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or _is_env_assignment_line(line):
            continue
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        user, command = parts[5], parts[6]
        entries.append((user, command))
    return entries


def _parse_user_cron_lines(text: str) -> list[str]:
    """Per-user crontab lines: min hour dom month dow command (no user field)."""
    entries = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or _is_env_assignment_line(line):
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        entries.append(parts[5])
    return entries


class PersistenceCollector:
    name = "persistence"
    respects_warmup = False  # rule 4 is live immediately per spec §7

    def __init__(
        self,
        system_unit_dirs: tuple[Path, ...] = DEFAULT_SYSTEM_UNIT_DIRS,
        user_unit_dir: Path | None = None,
        system_crontab: Path = DEFAULT_SYSTEM_CRONTAB,
        cron_d_dir: Path = DEFAULT_CRON_D_DIR,
        cron_periodic_dirs: tuple[Path, ...] = DEFAULT_CRON_PERIODIC_DIRS,
        user_crontab_dir: Path | None = None,
        autostart_dir: Path | None = None,
        shell_rc_files: tuple[Path, ...] | None = None,
        home: Path | None = None,
        current_username: str | None = None,
    ):
        home = home or Path.home()
        self._system_unit_dirs = system_unit_dirs
        self._user_unit_dir = user_unit_dir or (home / DEFAULT_USER_UNIT_DIR_RELATIVE)
        self._system_crontab = system_crontab
        self._cron_d_dir = cron_d_dir
        self._cron_periodic_dirs = cron_periodic_dirs
        self._user_crontab_dir = (
            user_crontab_dir if user_crontab_dir is not None else Platform().user_crontab_dir()
        )
        self._autostart_dir = autostart_dir or (home / DEFAULT_AUTOSTART_DIR_RELATIVE)
        self._shell_rc_files = (
            shell_rc_files
            if shell_rc_files is not None
            else tuple(home / name for name in DEFAULT_SHELL_RC_FILES_RELATIVE)
        )
        self._current_username = current_username if current_username is not None else _current_username()

    def collect(self, sink: ObservationSink) -> None:
        self._collect_systemd_units(sink)
        self._collect_systemd_timers(sink)
        self._collect_cron(sink)
        self._collect_autostart(sink)
        self._collect_shell_rc(sink)

    def _collect_systemd_units(self, sink: ObservationSink) -> None:
        for unit_dir in self._system_unit_dirs:
            for path in self._list_files(unit_dir, "*.service"):
                text = _read_text_or_none(path)
                if text is None:
                    continue
                exec_start = _parse_unit_exec_start(text)
                if exec_start is None:
                    continue
                sink.emit(
                    PersistenceEntryObservation(
                        mechanism="systemd_system",
                        unit_or_path=str(path),
                        command=exec_start,
                        owner_user=None,
                        enabled=None,  # precise enabled/disabled state not determined (see module docstring)
                    )
                )

        for path in self._list_files(self._user_unit_dir, "*.service"):
            text = _read_text_or_none(path)
            if text is None:
                continue
            exec_start = _parse_unit_exec_start(text)
            if exec_start is None:
                continue
            sink.emit(
                PersistenceEntryObservation(
                    mechanism="systemd_user",
                    unit_or_path=str(path),
                    command=exec_start,
                    owner_user=self._current_username,
                    enabled=None,
                )
            )

    def _collect_systemd_timers(self, sink: ObservationSink) -> None:
        all_timer_dirs = (*self._system_unit_dirs, self._user_unit_dir)
        for unit_dir in all_timer_dirs:
            for path in self._list_files(unit_dir, "*.timer"):
                text = _read_text_or_none(path)
                if text is None:
                    continue
                schedule = _parse_timer_schedule(text)
                if schedule is None:
                    continue
                sink.emit(
                    PersistenceEntryObservation(
                        mechanism="systemd_timer",
                        unit_or_path=str(path),
                        command=schedule,
                        owner_user=self._current_username if unit_dir == self._user_unit_dir else None,
                        enabled=None,
                    )
                )

    def _collect_cron(self, sink: ObservationSink) -> None:
        text = _read_text_or_none(self._system_crontab)
        if text is not None:
            for user, command in _parse_system_cron_lines(text):
                sink.emit(
                    PersistenceEntryObservation(
                        mechanism="cron",
                        unit_or_path=str(self._system_crontab),
                        command=command,
                        owner_user=user,
                        enabled=True,
                    )
                )

        for path in self._list_files(self._cron_d_dir, "*"):
            text = _read_text_or_none(path)
            if text is None:
                continue
            for user, command in _parse_system_cron_lines(text):
                sink.emit(
                    PersistenceEntryObservation(
                        mechanism="cron",
                        unit_or_path=str(path),
                        command=command,
                        owner_user=user,
                        enabled=True,
                    )
                )

        if self._user_crontab_dir is not None:
            for path in self._list_files(self._user_crontab_dir, "*"):
                text = _read_text_or_none(path)
                if text is None:
                    continue
                for command in _parse_user_cron_lines(text):
                    sink.emit(
                        PersistenceEntryObservation(
                            mechanism="cron",
                            unit_or_path=str(path),
                            command=command,
                            owner_user=path.name,  # spool file is named after the owning user
                            enabled=True,
                        )
                    )

        for periodic_dir in self._cron_periodic_dirs:
            for path in self._list_files(periodic_dir, "*"):
                sink.emit(
                    PersistenceEntryObservation(
                        mechanism="cron",
                        unit_or_path=str(path),
                        command=str(path),
                        owner_user=None,
                        enabled=True,
                    )
                )

    def _collect_autostart(self, sink: ObservationSink) -> None:
        for path in self._list_files(self._autostart_dir, "*.desktop"):
            text = _read_text_or_none(path)
            if text is None:
                continue
            exec_cmd, enabled = _parse_desktop_exec(text)
            if exec_cmd is None:
                continue
            sink.emit(
                PersistenceEntryObservation(
                    mechanism="autostart",
                    unit_or_path=str(path),
                    command=exec_cmd,
                    owner_user=self._current_username,
                    enabled=enabled,
                )
            )

    def _collect_shell_rc(self, sink: ObservationSink) -> None:
        for path in self._shell_rc_files:
            text = _read_text_or_none(path)
            if text is None:
                continue
            stripped = text.strip()
            if not stripped:
                continue
            sink.emit(
                PersistenceEntryObservation(
                    mechanism="shell_rc",
                    unit_or_path=str(path),
                    command=stripped,
                    owner_user=self._current_username,
                    enabled=None,
                )
            )

    @staticmethod
    def _list_files(directory: Path, pattern: str) -> list[Path]:
        if not directory.is_dir():
            return []
        return sorted(p for p in directory.glob(pattern) if p.is_file())
