from __future__ import annotations

from pathlib import Path

from sqlalchemy import select

from sentry.collectors.persistence import PersistenceCollector
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import PersistenceEntryRow


class FakeSink:
    def __init__(self):
        self.emitted = []

    def emit(self, observation):
        self.emitted.append(observation)


def _empty_dirs(tmp_path, *names) -> tuple[Path, ...]:
    """Paths that intentionally don't exist, to exercise 'not present -> no crash'."""
    return tuple(tmp_path / name for name in names)


def _base_collector(tmp_path, **overrides) -> PersistenceCollector:
    defaults = dict(
        system_unit_dirs=_empty_dirs(tmp_path, "no-system-units"),
        user_unit_dir=tmp_path / "no-user-units",
        system_crontab=tmp_path / "no-etc-crontab",
        cron_d_dir=tmp_path / "no-cron.d",
        cron_periodic_dirs=_empty_dirs(tmp_path, "no-cron.daily"),
        user_crontab_dir=tmp_path / "no-user-crontab-dir",
        autostart_dir=tmp_path / "no-autostart",
        shell_rc_files=(),
        current_username="alice",
    )
    defaults.update(overrides)
    return PersistenceCollector(**defaults)


def test_collect_parses_system_systemd_unit_exec_start(tmp_path):
    unit_dir = tmp_path / "system_units"
    unit_dir.mkdir()
    (unit_dir / "foo.service").write_text(
        "[Unit]\nDescription=Foo\n\n[Service]\nExecStart=/usr/bin/foo --daemon\n"
    )

    sink = FakeSink()
    _base_collector(tmp_path, system_unit_dirs=(unit_dir,)).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "systemd_system"]
    assert len(matches) == 1
    assert matches[0].command == "/usr/bin/foo --daemon"
    assert matches[0].unit_or_path == str(unit_dir / "foo.service")


def test_collect_skips_service_file_without_exec_start(tmp_path):
    unit_dir = tmp_path / "system_units"
    unit_dir.mkdir()
    (unit_dir / "empty.service").write_text("[Unit]\nDescription=No service section\n")

    sink = FakeSink()
    _base_collector(tmp_path, system_unit_dirs=(unit_dir,)).collect(sink)

    assert len([o for o in sink.emitted if o.mechanism == "systemd_system"]) == 0


def test_collect_parses_user_systemd_unit(tmp_path):
    user_unit_dir = tmp_path / "user_units"
    user_unit_dir.mkdir()
    (user_unit_dir / "bar.service").write_text("[Service]\nExecStart=/home/alice/.local/bin/bar\n")

    sink = FakeSink()
    _base_collector(tmp_path, user_unit_dir=user_unit_dir).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "systemd_user"]
    assert len(matches) == 1
    assert matches[0].command == "/home/alice/.local/bin/bar"
    assert matches[0].owner_user == "alice"


def test_collect_parses_systemd_timer_schedule(tmp_path):
    unit_dir = tmp_path / "system_units"
    unit_dir.mkdir()
    (unit_dir / "backup.timer").write_text("[Timer]\nOnCalendar=daily\n\n[Install]\nWantedBy=timers.target\n")

    sink = FakeSink()
    _base_collector(tmp_path, system_unit_dirs=(unit_dir,)).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "systemd_timer"]
    assert len(matches) == 1
    assert "OnCalendar=daily" in matches[0].command


def test_collect_parses_system_crontab_with_user_field(tmp_path):
    crontab = tmp_path / "crontab"
    crontab.write_text(
        "PATH=/usr/bin:/bin\n"
        "# a comment\n"
        "0 3 * * * root /usr/local/bin/backup.sh\n"
    )

    sink = FakeSink()
    _base_collector(tmp_path, system_crontab=crontab).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "cron"]
    assert len(matches) == 1
    assert matches[0].owner_user == "root"
    assert matches[0].command == "/usr/local/bin/backup.sh"


def test_collect_parses_cron_d_directory(tmp_path):
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    (cron_d / "myjob").write_text("*/5 * * * * www-data /opt/app/poll.sh\n")

    sink = FakeSink()
    _base_collector(tmp_path, cron_d_dir=cron_d).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "cron"]
    assert len(matches) == 1
    assert matches[0].owner_user == "www-data"
    assert matches[0].command == "/opt/app/poll.sh"


def test_collect_parses_user_crontab_spool_no_user_field(tmp_path):
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / "alice").write_text("30 2 * * * /home/alice/nightly.sh\n")

    sink = FakeSink()
    _base_collector(tmp_path, user_crontab_dir=spool).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "cron"]
    assert len(matches) == 1
    assert matches[0].owner_user == "alice"
    assert matches[0].command == "/home/alice/nightly.sh"


def test_collect_cron_periodic_dir_treats_each_file_as_entry(tmp_path):
    daily = tmp_path / "cron.daily"
    daily.mkdir()
    (daily / "logrotate").write_text("#!/bin/sh\nlogrotate /etc/logrotate.conf\n")

    sink = FakeSink()
    _base_collector(tmp_path, cron_periodic_dirs=(daily,)).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "cron"]
    assert len(matches) == 1
    assert matches[0].command == str(daily / "logrotate")


def test_collect_autostart_desktop_entry(tmp_path):
    autostart = tmp_path / "autostart"
    autostart.mkdir()
    (autostart / "sync.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=/usr/bin/sync-agent --tray\nHidden=false\n"
    )

    sink = FakeSink()
    _base_collector(tmp_path, autostart_dir=autostart).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "autostart"]
    assert len(matches) == 1
    assert matches[0].command == "/usr/bin/sync-agent --tray"
    assert matches[0].enabled is True


def test_collect_autostart_hidden_entry_marked_disabled(tmp_path):
    autostart = tmp_path / "autostart"
    autostart.mkdir()
    (autostart / "old.desktop").write_text("[Desktop Entry]\nExec=/usr/bin/old-tool\nHidden=true\n")

    sink = FakeSink()
    _base_collector(tmp_path, autostart_dir=autostart).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "autostart"]
    assert matches[0].enabled is False


def test_collect_shell_rc_file_content_as_command(tmp_path):
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("export PATH=$PATH:/opt/tool/bin\nalias ll='ls -la'\n")

    sink = FakeSink()
    _base_collector(tmp_path, shell_rc_files=(bashrc,)).collect(sink)

    matches = [o for o in sink.emitted if o.mechanism == "shell_rc"]
    assert len(matches) == 1
    assert "opt/tool/bin" in matches[0].command


def test_collect_skips_empty_shell_rc_file(tmp_path):
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("   \n")

    sink = FakeSink()
    _base_collector(tmp_path, shell_rc_files=(bashrc,)).collect(sink)

    assert len([o for o in sink.emitted if o.mechanism == "shell_rc"]) == 0


def test_collect_handles_all_sources_missing_without_crashing(tmp_path):
    sink = FakeSink()
    _base_collector(tmp_path).collect(sink)  # every source path points at nonexistent paths
    assert sink.emitted == []


def test_collect_drives_sink_correctly_end_to_end(tmp_path, session, fixed_clock):
    unit_dir = tmp_path / "system_units"
    unit_dir.mkdir()
    (unit_dir / "evil.service").write_text("[Service]\nExecStart=/tmp/.hidden/backdoor\n")

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle_time = sink.begin_cycle()
    _base_collector(tmp_path, system_unit_dirs=(unit_dir,)).collect(sink)

    rows = session.execute(select(PersistenceEntryRow)).scalars().all()
    assert len(rows) == 1
    assert rows[0].mechanism == "systemd_system"
    assert rows[0].command == "/tmp/.hidden/backdoor"
    assert rows[0].first_seen == cycle_time
    assert rows[0].still_present is True
