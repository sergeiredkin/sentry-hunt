from __future__ import annotations

import os
import threading

from sqlalchemy import select

from sentry.collectors.users import UsersCollector
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import UserAccountRow

PASSWD_CONTENT = """\
# comment line, should be skipped

root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
"""

GROUP_CONTENT = """\
# comment line, should be skipped

root:x:0:
sudo:x:27:alice
alice:x:1000:
bob:x:1001:
"""


class FakeSink:
    def __init__(self):
        self.emitted = []

    def emit(self, observation):
        self.emitted.append(observation)


def _write_fixture_files(tmp_path, passwd=PASSWD_CONTENT, group=GROUP_CONTENT):
    passwd_path = tmp_path / "passwd"
    group_path = tmp_path / "group"
    passwd_path.write_text(passwd)
    group_path.write_text(group)
    return str(passwd_path), str(group_path)


def test_collect_emits_observation_per_account(tmp_path):
    passwd_path, group_path = _write_fixture_files(tmp_path)

    sink = FakeSink()
    UsersCollector(passwd_path=passwd_path, group_path=group_path, sudo_group_names=("sudo", "wheel")).collect(sink)

    assert len(sink.emitted) == 3
    by_username = {o.username: o for o in sink.emitted}
    assert by_username["alice"].uid == 1000
    assert by_username["alice"].home_dir == "/home/alice"
    assert by_username["alice"].shell == "/bin/bash"


def test_collect_marks_sudo_group_member_as_sudoer(tmp_path):
    passwd_path, group_path = _write_fixture_files(tmp_path)

    sink = FakeSink()
    UsersCollector(passwd_path=passwd_path, group_path=group_path, sudo_group_names=("sudo", "wheel")).collect(sink)

    by_username = {o.username: o for o in sink.emitted}
    assert by_username["alice"].is_sudoer is True
    assert "sudo" in by_username["alice"].groups


def test_collect_non_member_not_marked_sudoer(tmp_path):
    passwd_path, group_path = _write_fixture_files(tmp_path)

    sink = FakeSink()
    UsersCollector(passwd_path=passwd_path, group_path=group_path, sudo_group_names=("sudo", "wheel")).collect(sink)

    by_username = {o.username: o for o in sink.emitted}
    assert by_username["bob"].is_sudoer is False
    assert by_username["root"].is_sudoer is False  # uid 0 alone does not imply sudo-group membership


def test_collect_marks_wheel_group_member_as_sudoer(tmp_path):
    passwd = "carol:x:1002:1002:Carol:/home/carol:/bin/bash\n"
    group = "carol:x:1002:\nwheel:x:10:carol\n"
    passwd_path, group_path = _write_fixture_files(tmp_path, passwd=passwd, group=group)

    sink = FakeSink()
    UsersCollector(passwd_path=passwd_path, group_path=group_path, sudo_group_names=("sudo", "wheel")).collect(sink)

    assert sink.emitted[0].is_sudoer is True


def test_collect_includes_primary_group_even_when_not_listed_as_member(tmp_path):
    passwd_path, group_path = _write_fixture_files(tmp_path)

    sink = FakeSink()
    UsersCollector(passwd_path=passwd_path, group_path=group_path, sudo_group_names=("sudo", "wheel")).collect(sink)

    by_username = {o.username: o for o in sink.emitted}
    assert "bob" in by_username["bob"].groups  # primary group, not in members list of /etc/group


def test_collect_degrades_gracefully_when_passwd_missing(tmp_path):
    _, group_path = _write_fixture_files(tmp_path)
    missing_passwd = str(tmp_path / "no-such-passwd")

    sink = FakeSink()
    UsersCollector(passwd_path=missing_passwd, group_path=group_path).collect(sink)  # must not raise

    assert len(sink.emitted) == 0


def test_collect_degrades_gracefully_when_group_missing(tmp_path):
    passwd_path, _ = _write_fixture_files(tmp_path)
    missing_group = str(tmp_path / "no-such-group")

    sink = FakeSink()
    UsersCollector(passwd_path=passwd_path, group_path=missing_group, sudo_group_names=("sudo",)).collect(sink)

    assert len(sink.emitted) == 3  # still emits accounts, just without group data
    assert all(o.groups == () for o in sink.emitted)


def test_collect_drives_sink_correctly_end_to_end(tmp_path, session, fixed_clock):
    passwd_path, group_path = _write_fixture_files(tmp_path)

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle_time = sink.begin_cycle()
    UsersCollector(passwd_path=passwd_path, group_path=group_path, sudo_group_names=("sudo", "wheel")).collect(sink)

    rows = session.execute(select(UserAccountRow)).scalars().all()
    assert len(rows) == 3
    alice = next(r for r in rows if r.username == "alice")
    assert alice.is_sudoer is True
    assert alice.first_seen == cycle_time


def test_collect_does_not_hang_when_passwd_path_is_a_fifo(tmp_path):
    # group file lives at a *different* path than the FIFO -- writing
    # fixture content to the same path as the FIFO would itself block
    # (open(fifo, "w") also waits for a reader), which isn't what this
    # test is trying to exercise.
    group_path = tmp_path / "group"
    group_path.write_text(GROUP_CONTENT)

    fifo_path = tmp_path / "passwd"
    os.mkfifo(fifo_path)

    sink = FakeSink()
    result: dict[str, object] = {}

    def call():
        UsersCollector(passwd_path=str(fifo_path), group_path=str(group_path)).collect(sink)
        result["done"] = True

    t = threading.Thread(target=call, daemon=True)
    t.start()
    t.join(timeout=5)

    assert not t.is_alive(), "collect() blocked on a FIFO instead of degrading gracefully"
    assert result.get("done") is True
    assert sink.emitted == []
