from __future__ import annotations

import grp

import pytest

from sentry.platform import base as platform_base
from sentry.platform.base import Platform


@pytest.fixture(autouse=True)
def _clear_unit_names_cache():
    platform_base._installed_unit_names.cache_clear()
    yield
    platform_base._installed_unit_names.cache_clear()


def test_sudo_group_names_returns_only_present_candidates(monkeypatch):
    def fake_getgrnam(name):
        if name == "sudo":
            return object()
        raise KeyError(name)

    monkeypatch.setattr(platform_base.grp, "getgrnam", fake_getgrnam)
    assert Platform().sudo_group_names() == ["sudo"]


def test_sudo_group_names_returns_both_when_both_present(monkeypatch):
    monkeypatch.setattr(platform_base.grp, "getgrnam", lambda name: object())
    assert Platform().sudo_group_names() == ["sudo", "wheel"]


def test_sudo_group_names_returns_empty_when_neither_present(monkeypatch):
    def fake_getgrnam(name):
        raise KeyError(name)

    monkeypatch.setattr(platform_base.grp, "getgrnam", fake_getgrnam)
    assert Platform().sudo_group_names() == []


class _FakeCompletedProcess:
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


def test_ssh_service_units_detects_debian_style_unit(monkeypatch):
    monkeypatch.setattr(
        platform_base.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess("ssh.service                     enabled\n"),
    )
    assert Platform().ssh_service_units() == ["ssh"]


def test_ssh_service_units_detects_rhel_style_unit(monkeypatch):
    monkeypatch.setattr(
        platform_base.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess("sshd.service                    enabled\n"),
    )
    assert Platform().ssh_service_units() == ["sshd"]


def test_ssh_service_units_empty_when_neither_installed(monkeypatch):
    monkeypatch.setattr(
        platform_base.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess("nginx.service                   enabled\n"),
    )
    assert Platform().ssh_service_units() == []


def test_ssh_service_units_empty_when_systemctl_missing(monkeypatch):
    def raise_missing(*a, **k):
        raise FileNotFoundError("systemctl not found")

    monkeypatch.setattr(platform_base.subprocess, "run", raise_missing)
    assert Platform().ssh_service_units() == []


def test_ssh_service_units_empty_on_nonzero_returncode(monkeypatch):
    monkeypatch.setattr(
        platform_base.subprocess, "run", lambda *a, **k: _FakeCompletedProcess("", returncode=1)
    )
    assert Platform().ssh_service_units() == []


def test_user_crontab_dir_prefers_debian_style_when_present(monkeypatch, tmp_path):
    debian_style = tmp_path / "crontabs"
    debian_style.mkdir()
    rhel_style = tmp_path / "cron"
    rhel_style.mkdir()

    monkeypatch.setattr(platform_base, "_USER_CRONTAB_DIR_CANDIDATES", (debian_style, rhel_style))
    assert Platform().user_crontab_dir() == debian_style


def test_user_crontab_dir_falls_back_to_rhel_style(monkeypatch, tmp_path):
    debian_style = tmp_path / "no-crontabs-dir"
    rhel_style = tmp_path / "cron"
    rhel_style.mkdir()

    monkeypatch.setattr(platform_base, "_USER_CRONTAB_DIR_CANDIDATES", (debian_style, rhel_style))
    assert Platform().user_crontab_dir() == rhel_style


def test_user_crontab_dir_none_when_neither_exists(monkeypatch, tmp_path):
    monkeypatch.setattr(
        platform_base,
        "_USER_CRONTAB_DIR_CANDIDATES",
        (tmp_path / "no-a", tmp_path / "no-b"),
    )
    assert Platform().user_crontab_dir() is None
