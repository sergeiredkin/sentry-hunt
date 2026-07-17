from __future__ import annotations

import hashlib

import psutil
import pytest
from sqlalchemy import select

from sentry.collectors._common import hash_file
from sentry.collectors.process import ProcessCollector
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import ProcessObservationRow


class FakeProcess:
    def __init__(
        self,
        pid,
        ppid=1,
        create_time=1000.0,
        exe="/usr/bin/foo",
        cmdline=None,
        username="alice",
        raise_ppid=None,
        raise_exe=None,
        raise_cmdline=None,
        raise_username=None,
    ):
        self.pid = pid
        self._ppid = ppid
        self._create_time = create_time
        self._exe = exe
        self._cmdline = cmdline if cmdline is not None else [exe]
        self._username = username
        self._raise_ppid = raise_ppid
        self._raise_exe = raise_exe
        self._raise_cmdline = raise_cmdline
        self._raise_username = raise_username

    def ppid(self):
        if self._raise_ppid:
            raise self._raise_ppid
        return self._ppid

    def create_time(self):
        return self._create_time

    def exe(self):
        if self._raise_exe:
            raise self._raise_exe
        return self._exe

    def cmdline(self):
        if self._raise_cmdline:
            raise self._raise_cmdline
        return self._cmdline

    def username(self):
        if self._raise_username:
            raise self._raise_username
        return self._username


class FakeSink:
    def __init__(self):
        self.emitted = []

    def emit(self, observation):
        self.emitted.append(observation)


def _patch_psutil(monkeypatch, procs: dict[int, FakeProcess]):
    monkeypatch.setattr("sentry.collectors.process.psutil.pids", lambda: list(procs.keys()))

    def fake_process_ctor(pid):
        return procs[pid]

    monkeypatch.setattr("sentry.collectors.process.psutil.Process", fake_process_ctor)


def test_collect_emits_one_observation_per_pid(monkeypatch):
    procs = {
        1: FakeProcess(1, ppid=0, exe="/usr/bin/init", cmdline=["/usr/bin/init"], username="root"),
        100: FakeProcess(100, ppid=1, exe="/usr/bin/bash", cmdline=["bash", "-c", "ls"], username="alice"),
    }
    _patch_psutil(monkeypatch, procs)

    sink = FakeSink()
    ProcessCollector().collect(sink)

    assert len(sink.emitted) == 2
    by_pid = {o.pid: o for o in sink.emitted}
    assert by_pid[100].ppid == 1
    assert by_pid[100].exe_path == "/usr/bin/bash"
    assert by_pid[100].cmdline == "bash -c ls"
    assert by_pid[100].user == "alice"
    assert by_pid[100].create_time == 1000.0


def test_collect_skips_process_that_exited_before_inspection(monkeypatch):
    procs = {
        1: FakeProcess(1),
        2: FakeProcess(2, raise_ppid=psutil.NoSuchProcess(2)),
    }
    _patch_psutil(monkeypatch, procs)

    sink = FakeSink()
    ProcessCollector().collect(sink)

    assert len(sink.emitted) == 1
    assert sink.emitted[0].pid == 1


def test_collect_skips_zombie_process(monkeypatch):
    procs = {1: FakeProcess(1, raise_ppid=psutil.ZombieProcess(1))}
    _patch_psutil(monkeypatch, procs)

    sink = FakeSink()
    ProcessCollector().collect(sink)

    assert len(sink.emitted) == 0


def test_collect_degrades_gracefully_on_access_denied(monkeypatch):
    procs = {
        1: FakeProcess(
            1,
            ppid=0,
            exe="/usr/bin/other-users-proc",
            raise_exe=psutil.AccessDenied(1),
            raise_cmdline=psutil.AccessDenied(1),
            raise_username=psutil.AccessDenied(1),
        )
    }
    _patch_psutil(monkeypatch, procs)

    sink = FakeSink()
    ProcessCollector().collect(sink)

    assert len(sink.emitted) == 1
    obs = sink.emitted[0]
    assert obs.pid == 1
    assert obs.ppid == 0  # ppid() itself did not raise
    assert obs.exe_path is None
    assert obs.cmdline == ""
    assert obs.user is None
    assert obs.sha256 is None  # no exe_path to hash


def test_hash_file_computes_correct_sha256(tmp_path):
    f = tmp_path / "somebinary"
    f.write_bytes(b"hello world" * 1000)
    expected = hashlib.sha256(b"hello world" * 1000).hexdigest()
    assert hash_file(str(f)) == expected


def test_hash_file_returns_none_for_missing_path(tmp_path):
    missing = tmp_path / "does-not-exist"
    assert hash_file(str(missing)) is None


def test_collect_drives_sink_correctly_end_to_end(monkeypatch, session, fixed_clock):
    """Spec §13 task 3: 'implement process.py first; test it drives the sink
    correctly.' Exercises the real SqlAlchemyObservationSink + interval
    upsert against an in-memory DB, not a fake."""
    procs = {
        100: FakeProcess(100, ppid=1, create_time=1000.0, exe="/usr/bin/bash", cmdline=["bash"], username="alice"),
    }
    _patch_psutil(monkeypatch, procs)

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle_time = sink.begin_cycle()
    ProcessCollector().collect(sink)

    rows = session.execute(select(ProcessObservationRow)).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.pid == 100
    assert row.exe_path == "/usr/bin/bash"
    assert row.first_seen == cycle_time
    assert row.last_seen == cycle_time
    assert row.still_present is True
