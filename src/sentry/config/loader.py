"""Application configuration loaded from TOML with environment overrides."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AppConfig:
    snapshot_interval_seconds: float = 60.0
    warmup_days: float = 7.0
    skip_warmup: bool = False
    auth_per_account_threshold: int = 5
    auth_total_threshold: int = 10
    auth_window_minutes: float = 10.0
    journal_lookback_minutes: float = 15.0
    critical_paths: tuple[str, ...] = field(default_factory=tuple)

    @property
    def auth_window(self) -> timedelta:
        return timedelta(minutes=self.auth_window_minutes)

    @property
    def journal_lookback(self) -> timedelta:
        return timedelta(minutes=self.journal_lookback_minutes)


def _config_path() -> Path:
    return Path(os.environ.get("SENTRY_CONFIG_PATH", "~/.config/sentry/config.toml")).expanduser()


def _env_value(name: str, default: Any, converter):
    value = os.environ.get(name)
    return default if value is None else converter(value)


def load_config(path: Path | None = None) -> AppConfig:
    """Load defaults, an optional TOML file, then SENTRY_* overrides."""
    values: dict[str, Any] = {}
    config_path = path or _config_path()
    if config_path.is_file():
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
        values.update(raw.get("sentry", raw))

    def value(key: str, env_name: str, default: Any, converter):
        file_value = values.get(key, default)
        return _env_value(env_name, file_value, converter)

    paths = values.get("critical_paths", [])
    if os.environ.get("SENTRY_CRITICAL_PATHS"):
        paths = [p for p in os.environ["SENTRY_CRITICAL_PATHS"].split(":") if p]
    return AppConfig(
        snapshot_interval_seconds=value("snapshot_interval_seconds", "SENTRY_SNAPSHOT_INTERVAL_SECONDS", 60.0, float),
        warmup_days=value("warmup_days", "SENTRY_WARMUP_DAYS", 7.0, float),
        skip_warmup=value("skip_warmup", "SENTRY_SKIP_WARMUP", False, lambda v: str(v).lower() in {"1", "true", "yes", "on"}),
        auth_per_account_threshold=value("auth_per_account_threshold", "SENTRY_AUTH_PER_ACCOUNT_THRESHOLD", 5, int),
        auth_total_threshold=value("auth_total_threshold", "SENTRY_AUTH_TOTAL_THRESHOLD", 10, int),
        auth_window_minutes=value("auth_window_minutes", "SENTRY_AUTH_WINDOW_MINUTES", 10.0, float),
        journal_lookback_minutes=value("journal_lookback_minutes", "SENTRY_JOURNAL_LOOKBACK_MINUTES", 15.0, float),
        critical_paths=tuple(paths),
    )
