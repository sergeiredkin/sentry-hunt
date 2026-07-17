from __future__ import annotations

import hashlib
import os
import stat as stat_module

from sqlalchemy import select

from sentry.collectors.file_integrity import (
    DEFAULT_CRITICAL_BINARIES,
    DEFAULT_CRITICAL_FILES,
    FileIntegrityCollector,
    default_critical_paths,
)
from sentry.engine.sink import SqlAlchemyObservationSink
from sentry.storage.models import FileIntegrityRow


class FakeSink:
    def __init__(self):
        self.emitted = []

    def emit(self, observation):
        self.emitted.append(observation)


def test_collect_emits_observation_for_existing_file(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_bytes(b"PermitRootLogin no\n")
    os.chmod(f, 0o644)

    sink = FakeSink()
    FileIntegrityCollector(paths=(str(f),)).collect(sink)

    assert len(sink.emitted) == 1
    obs = sink.emitted[0]
    assert obs.path == str(f)
    assert obs.sha256 == hashlib.sha256(b"PermitRootLogin no\n").hexdigest()
    assert obs.size_bytes == len(b"PermitRootLogin no\n")
    assert obs.perms_octal == "644"
    assert obs.mtime is not None


def test_collect_skips_missing_file(tmp_path):
    missing = tmp_path / "does-not-exist"

    sink = FakeSink()
    FileIntegrityCollector(paths=(str(missing),)).collect(sink)

    assert len(sink.emitted) == 0


def test_collect_sha256_null_for_unreadable_file(tmp_path):
    f = tmp_path / "shadow"
    f.write_bytes(b"root:!:19000:0:99999:7:::\n")
    os.chmod(f, 0o000)

    try:
        sink = FakeSink()
        FileIntegrityCollector(paths=(str(f),)).collect(sink)

        assert len(sink.emitted) == 1
        assert sink.emitted[0].sha256 is None
        assert sink.emitted[0].perms_octal == "000"
    finally:
        os.chmod(f, 0o644)  # restore so tmp_path cleanup can remove it


def test_collect_permission_change_visible_in_perms_octal(tmp_path):
    f = tmp_path / "authorized_keys"
    f.write_bytes(b"ssh-ed25519 AAAA...\n")
    os.chmod(f, 0o600)

    sink = FakeSink()
    FileIntegrityCollector(paths=(str(f),)).collect(sink)
    assert sink.emitted[0].perms_octal == "600"

    os.chmod(f, 0o644)
    sink2 = FakeSink()
    FileIntegrityCollector(paths=(str(f),)).collect(sink2)
    assert sink2.emitted[0].perms_octal == "644"


def test_default_critical_paths_includes_fixed_files_home_ssh_and_binaries(tmp_path):
    home = tmp_path / "home" / "alice"
    (home / ".ssh").mkdir(parents=True)
    local_bin = tmp_path / "usr_local_bin"
    local_bin.mkdir()
    (local_bin / "customtool").write_bytes(b"#!/bin/sh\n")
    sudoers_d = tmp_path / "sudoers.d"
    sudoers_d.mkdir()
    (sudoers_d / "90-cloud-init-users").write_bytes(b"alice ALL=(ALL) NOPASSWD:ALL\n")

    paths = default_critical_paths(home=home, local_bin_dir=local_bin, sudoers_d_dir=sudoers_d)

    for fixed in DEFAULT_CRITICAL_FILES:
        assert fixed in paths
    for binary in DEFAULT_CRITICAL_BINARIES:
        assert binary in paths
    assert str(home / ".ssh" / "authorized_keys") in paths
    assert str(home / ".ssh" / "config") in paths
    assert str(local_bin / "customtool") in paths
    assert str(sudoers_d / "90-cloud-init-users") in paths


def test_default_critical_paths_handles_missing_local_bin_dir(tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    missing_local_bin = tmp_path / "no-such-dir"

    paths = default_critical_paths(home=home, local_bin_dir=missing_local_bin)

    assert all("no-such-dir" not in p for p in paths)
    for fixed in DEFAULT_CRITICAL_FILES:
        assert fixed in paths


def test_collect_drives_sink_correctly_end_to_end(tmp_path, session, fixed_clock):
    f = tmp_path / "passwd"
    f.write_bytes(b"root:x:0:0:root:/root:/bin/bash\n")
    os.chmod(f, 0o644)

    sink = SqlAlchemyObservationSink(session, clock=fixed_clock)
    cycle_time = sink.begin_cycle()
    FileIntegrityCollector(paths=(str(f),)).collect(sink)

    rows = session.execute(select(FileIntegrityRow)).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.path == str(f)
    assert row.first_seen == cycle_time
    assert row.still_present is True
