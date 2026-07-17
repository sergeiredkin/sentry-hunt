from __future__ import annotations

from tests.conftest import make_network_observation, make_process_observation


def test_identity_key_deterministic():
    a = make_process_observation()
    b = make_process_observation()
    assert a.identity_key == b.identity_key


def test_process_identity_sensitive_to_pid():
    a = make_process_observation(pid=1234)
    b = make_process_observation(pid=5678)
    assert a.identity_key != b.identity_key


def test_process_identity_sensitive_to_ppid():
    a = make_process_observation(ppid=1)
    b = make_process_observation(ppid=2)
    assert a.identity_key != b.identity_key


def test_process_identity_sensitive_to_exe_path():
    a = make_process_observation(exe_path="/usr/bin/bash")
    b = make_process_observation(exe_path="/usr/bin/zsh")
    assert a.identity_key != b.identity_key


def test_process_identity_sensitive_to_create_time():
    a = make_process_observation(create_time=1000.0)
    b = make_process_observation(create_time=1000.01)
    assert a.identity_key != b.identity_key


def test_process_identity_subsecond_precision_not_rounded_away():
    a = make_process_observation(create_time=1000.001)
    b = make_process_observation(create_time=1000.002)
    assert a.identity_key != b.identity_key


def test_process_identity_insensitive_to_mutable_fields():
    a = make_process_observation(sha256="a" * 64, cmdline="bash", user="alice")
    b = make_process_observation(sha256="c" * 64, cmdline="bash -c ls", user="bob")
    assert a.identity_key == b.identity_key


def test_network_identity_sensitive_to_port_and_pid():
    a = make_network_observation(lport=8080, pid=100)
    b = make_network_observation(lport=8080, pid=200)
    assert a.identity_key != b.identity_key

    c = make_network_observation(lport=8080)
    d = make_network_observation(lport=9090)
    assert c.identity_key != d.identity_key


def test_network_identity_insensitive_to_mutable_fields():
    a = make_network_observation(exe_path="/usr/bin/python3", sha256="b" * 64, status="LISTEN")
    b = make_network_observation(exe_path="/usr/bin/python3.11", sha256="d" * 64, status="ESTABLISHED")
    assert a.identity_key == b.identity_key
