from sentry.config.loader import load_config


def test_defaults_are_safe_and_documented(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTRY_CONFIG_PATH", raising=False)
    config = load_config(tmp_path / "missing.toml")

    assert config.snapshot_interval_seconds == 60
    assert config.warmup_days == 7
    assert config.auth_per_account_threshold == 5
    assert config.auth_total_threshold == 10
    assert config.critical_paths == ()


def test_toml_and_environment_overrides(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(
        """[sentry]\nsnapshot_interval_seconds = 12\nauth_total_threshold = 20\ncritical_paths = [\"/etc/hosts\"]\n"""
    )
    monkeypatch.setenv("SENTRY_SNAPSHOT_INTERVAL_SECONDS", "3")
    monkeypatch.setenv("SENTRY_SKIP_WARMUP", "true")

    config = load_config(path)

    assert config.snapshot_interval_seconds == 3
    assert config.auth_total_threshold == 20
    assert config.skip_warmup is True
    assert config.critical_paths == ("/etc/hosts",)


def test_colon_separated_critical_paths_environment_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRY_CRITICAL_PATHS", "/one:/two")

    config = load_config(tmp_path / "missing.toml")

    assert config.critical_paths == ("/one", "/two")
