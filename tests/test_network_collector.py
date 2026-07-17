from __future__ import annotations

import socket
from collections import namedtuple

import psutil
from sqlalchemy import select

from sentry.collectors.network import NetworkCollector
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import NetworkObservationRow

FakeConn = namedtuple("FakeConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def make_conn(laddr=("0.0.0.0", 8080), raddr=(), status="LISTEN", pid=100, conn_type=socket.SOCK_STREAM):
    return FakeConn(fd=3, family=socket.AF_INET, type=conn_type, laddr=laddr, raddr=raddr, status=status, pid=pid)


class FakeProcess:
    def __init__(self, exe="/usr/bin/nginx", username="root", raise_exe=None, raise_username=None):
        self._exe = exe
        self._username = username
        self._raise_exe = raise_exe
        self._raise_username = raise_username

    def exe(self):
        if self._raise_exe:
            raise self._raise_exe
        return self._exe

    def username(self):
        if self._raise_username:
            raise self._raise_username
        return self._username


class FakeSink:
    def __init__(self):
        self.emitted = []

    def emit(self, observation):
        self.emitted.append(observation)


def _patch_net_connections(monkeypatch, conns):
    monkeypatch.setattr("sentry.collectors.network.psutil.net_connections", lambda kind="inet": conns)


def _patch_process(monkeypatch, procs: dict[int, FakeProcess]):
    def fake_process_ctor(pid):
        return procs[pid]

    monkeypatch.setattr("sentry.collectors.network.psutil.Process", fake_process_ctor)


def test_collect_emits_listen_socket(monkeypatch):
    _patch_net_connections(monkeypatch, [make_conn(laddr=("0.0.0.0", 22), status="LISTEN", pid=100)])
    _patch_process(monkeypatch, {100: FakeProcess(exe="/usr/sbin/sshd", username="root")})

    sink = FakeSink()
    NetworkCollector().collect(sink)

    assert len(sink.emitted) == 1
    obs = sink.emitted[0]
    assert obs.protocol == "tcp"
    assert obs.laddr == "0.0.0.0"
    assert obs.lport == 22
    assert obs.status == "LISTEN"
    assert obs.exe_path == "/usr/sbin/sshd"
    assert obs.user == "root"


def test_collect_emits_established_socket(monkeypatch):
    _patch_net_connections(
        monkeypatch,
        [make_conn(laddr=("192.168.1.5", 443), raddr=("8.8.8.8", 51000), status="ESTABLISHED", pid=200)],
    )
    _patch_process(monkeypatch, {200: FakeProcess()})

    sink = FakeSink()
    NetworkCollector().collect(sink)

    assert len(sink.emitted) == 1
    obs = sink.emitted[0]
    assert obs.status == "ESTABLISHED"
    assert obs.raddr == "8.8.8.8"
    assert obs.rport == 51000


def test_collect_skips_transient_tcp_states(monkeypatch):
    _patch_net_connections(monkeypatch, [make_conn(status="TIME_WAIT", pid=None)])
    _patch_process(monkeypatch, {})

    sink = FakeSink()
    NetworkCollector().collect(sink)

    assert len(sink.emitted) == 0


def test_collect_includes_udp_bound_socket(monkeypatch):
    _patch_net_connections(
        monkeypatch,
        [make_conn(laddr=("0.0.0.0", 53), status="NONE", pid=300, conn_type=socket.SOCK_DGRAM)],
    )
    _patch_process(monkeypatch, {300: FakeProcess(exe="/usr/sbin/dnsmasq")})

    sink = FakeSink()
    NetworkCollector().collect(sink)

    assert len(sink.emitted) == 1
    assert sink.emitted[0].protocol == "udp"
    assert sink.emitted[0].lport == 53


def test_collect_pid_none_leaves_owner_fields_null(monkeypatch):
    _patch_net_connections(monkeypatch, [make_conn(status="LISTEN", pid=None)])
    _patch_process(monkeypatch, {})

    sink = FakeSink()
    NetworkCollector().collect(sink)

    assert len(sink.emitted) == 1
    obs = sink.emitted[0]
    assert obs.pid is None
    assert obs.exe_path is None
    assert obs.sha256 is None
    assert obs.user is None


def test_collect_degrades_gracefully_when_net_connections_denied(monkeypatch):
    def raise_denied(kind="inet"):
        raise psutil.AccessDenied()

    monkeypatch.setattr("sentry.collectors.network.psutil.net_connections", raise_denied)

    sink = FakeSink()
    NetworkCollector().collect(sink)  # must not raise

    assert len(sink.emitted) == 0


def test_collect_drives_sink_correctly_end_to_end(monkeypatch, session, fixed_clock):
    _patch_net_connections(monkeypatch, [make_conn(laddr=("0.0.0.0", 8080), status="LISTEN", pid=100)])
    _patch_process(monkeypatch, {100: FakeProcess(exe="/usr/bin/python3", username="alice")})

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle_time = sink.begin_cycle()
    NetworkCollector().collect(sink)

    rows = session.execute(select(NetworkObservationRow)).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.lport == 8080
    assert row.status == "LISTEN"
    assert row.first_seen == cycle_time
    assert row.still_present is True
