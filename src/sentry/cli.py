"""CLI entry point: `sentry run` (batch cycles, console output) and
`sentry tui` (the interactive Textual dashboard, tui/app.py)."""

from __future__ import annotations

import argparse
import re
import json
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from sentry.collectors._common import HashCache
from sentry.config.loader import AppConfig, load_config
from sentry.collectors.file_integrity import FileIntegrityCollector
from sentry.collectors.journal_auth import JournalAuthCollector
from sentry.collectors.network import NetworkCollector
from sentry.collectors.persistence import PersistenceCollector
from sentry.collectors.process import ProcessCollector
from sentry.collectors.users import UsersCollector
from sentry.engine.pipeline import run_cycle
from sentry.rules.r1_new_executable import NewExecutableRule
from sentry.rules.r2_priv_change import PrivilegeChangeRule
from sentry.rules.r3_new_listener import NewListenerRule
from sentry.rules.r4_persistence import PersistenceRule
from sentry.rules.r5_auth_anomaly import AuthAnomalyRule
from sentry.rules.r6_critical_change import CriticalChangeRule
from sentry.storage.db import make_engine, resolve_db_path
from sentry.storage.models import AlertRow

# Strips ASCII control characters (including ESC, newline, tab) from text
# before it's printed to a raw terminal. Evidence fields like a process's
# exe_path come from attacker-controllable filenames -- Linux allows any
# byte except NUL and '/' in a filename, including raw terminal escape
# sequences -- so printing them unsanitized via plain print() would let a
# crafted path inject terminal control codes, or fake extra output lines,
# into the console.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_for_terminal(s: str) -> str:
    return _CONTROL_CHAR_RE.sub("", s)


def _build_collectors(config: AppConfig | None = None):
    config = config or load_config()
    # Shared across Process/NetworkCollector so a binary hashed once (by
    # either collector, in either cycle) is never re-hashed while its
    # mtime+size stay the same -- see HashCache's docstring. Returned
    # alongside the collectors so the caller can pass it to run_cycle(),
    # which clears it at the start of every cycle (must not outlive one
    # cycle -- see run_cycle()'s docstring).
    hash_cache = HashCache()
    collectors = [
        ProcessCollector(hash_cache=hash_cache),
        NetworkCollector(hash_cache=hash_cache),
        UsersCollector(),
        PersistenceCollector(),
        FileIntegrityCollector(paths=config.critical_paths or None),
        JournalAuthCollector(lookback=config.journal_lookback),
    ]
    return collectors, hash_cache


def _build_rules(config: AppConfig | None = None):
    config = config or load_config()
    return [
        NewExecutableRule(),
        PrivilegeChangeRule(),
        NewListenerRule(),
        PersistenceRule(),
        AuthAnomalyRule(
            per_account_threshold=config.auth_per_account_threshold,
            total_threshold=config.auth_total_threshold,
            window=config.auth_window,
        ),
        CriticalChangeRule(),
    ]


def _ensure_migrated() -> None:
    pkg_root = Path(__file__).resolve().parent
    ini_path = pkg_root / "alembic.ini"
    cfg = Config(str(ini_path))
    command.upgrade(cfg, "head")


def _run_collection_cycle(session, collectors, rules, previous, hash_cache, config):
    t0 = time.monotonic()
    previous, findings = run_cycle(
        session, collectors, rules, previous, hash_cache=hash_cache, config=config
    )
    return previous, findings, time.monotonic() - t0


def cmd_run(args: argparse.Namespace) -> None:
    _ensure_migrated()
    config = load_config()
    interval = config.snapshot_interval_seconds if args.interval is None else args.interval
    print(f"DB: {resolve_db_path()}")
    engine = make_engine()

    with Session(engine) as session:
        collectors, hash_cache = _build_collectors(config)
        rules = _build_rules(config)
        previous = None

        for i in range(args.cycles):
            print(f"\n--- cycle {i + 1}/{args.cycles} ---")
            previous, findings, elapsed = _run_collection_cycle(
                session, collectors, rules, previous, hash_cache, config
            )
            print(f"  collected+evaluated in {elapsed:.1f}s")

            if not findings:
                print("  no surfaced findings")
            else:
                for f in findings:
                    print(f"  [{f.severity:6s}] {f.rule_id} {_sanitize_for_terminal(f.title)}")

            if i < args.cycles - 1:
                time.sleep(interval)


def cmd_investigate(args: argparse.Namespace) -> None:
    """Hand a Sentry alert to spoorlog for a live forensic scan."""
    _ensure_migrated()
    with Session(make_engine()) as session:
        alert = session.get(AlertRow, args.alert_id)
        if alert is None:
            raise SystemExit(f"alert {args.alert_id} not found")
        context = {
            "source": "sentry",
            "alert_id": alert.id,
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "title": alert.title,
            "created_at": alert.created_at.isoformat(),
            "evidence": json.loads(alert.evidence_json),
        }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        json.dump(context, handle, indent=2)
        context_path = handle.name
    try:
        command = [args.spoorlog, "--report"]
        if args.output:
            command.append(args.output)
        command.extend(["--context", context_path])
        result = subprocess.run(command, check=False)
    finally:
        Path(context_path).unlink(missing_ok=True)
    raise SystemExit(result.returncode)


def cmd_daemon(args: argparse.Namespace) -> None:
    """Run collection continuously; intended for systemd."""
    _ensure_migrated()
    config = load_config()
    interval = config.snapshot_interval_seconds if args.interval is None else args.interval
    engine = make_engine()
    stop = False

    def request_stop(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    print(f"Sentry daemon started; DB: {resolve_db_path()}", flush=True)

    with Session(engine) as session:
        collectors, hash_cache = _build_collectors(config)
        rules = _build_rules(config)
        previous = None
        while not stop:
            previous, findings, elapsed = _run_collection_cycle(
                session, collectors, rules, previous, hash_cache, config
            )
            print(f"cycle complete in {elapsed:.1f}s; surfaced findings={len(findings)}", flush=True)
            stop = stop or not _sleep_interruptibly(interval, lambda: stop)
    print("Sentry daemon stopped", flush=True)


def _sleep_interruptibly(seconds: float, stopped) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if stopped():
            return False
        time.sleep(min(1.0, deadline - time.monotonic()))
    return True


def cmd_tui(args: argparse.Namespace) -> None:
    _ensure_migrated()
    config = load_config()
    from sentry.tui.app import run_tui

    interval = config.snapshot_interval_seconds if args.interval is None else args.interval
    run_tui(cycle_interval=interval)


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentry")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Run collection+evaluation cycles, printing findings to the console")
    run_parser.add_argument("--cycles", type=int, default=2, help="number of cycles to run")
    run_parser.add_argument("--interval", type=float, default=None, help="seconds between cycles (default: config, 60)")
    run_parser.set_defaults(func=cmd_run)

    investigate_parser = sub.add_parser(
        "investigate", help="Run spoorlog against a Sentry alert and preserve context"
    )
    investigate_parser.add_argument("alert_id", type=int, help="Sentry alert ID")
    investigate_parser.add_argument("--spoorlog", default="spoorlog", help="spoorlog executable")
    investigate_parser.add_argument("--output", help="spoorlog report output path")
    investigate_parser.set_defaults(func=cmd_investigate)

    daemon_parser = sub.add_parser("daemon", help="Run continuously; intended for systemd")
    daemon_parser.add_argument("--interval", type=float, default=None, help="seconds between cycles (default: config, 60)")
    daemon_parser.set_defaults(func=cmd_daemon)

    tui_parser = sub.add_parser("tui", help="Launch the interactive dashboard")
    tui_parser.add_argument("--interval", type=float, default=None, help="seconds between background collection cycles (default: config, 60)")
    tui_parser.set_defaults(func=cmd_tui)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
