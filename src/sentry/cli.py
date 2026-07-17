"""CLI entry point: `sentry run` (batch cycles, console output) and
`sentry tui` (the interactive Textual dashboard, tui/app.py)."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from sentry.collectors._common import HashCache
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


def _build_collectors():
    # Shared across Process/NetworkCollector so a binary hashed once (by
    # either collector, in either cycle) is never re-hashed while its
    # mtime+size stay the same -- see HashCache's docstring.
    hash_cache = HashCache()
    return [
        ProcessCollector(hash_cache=hash_cache),
        NetworkCollector(hash_cache=hash_cache),
        UsersCollector(),
        PersistenceCollector(),
        FileIntegrityCollector(),
        JournalAuthCollector(),
    ]


def _build_rules():
    return [
        NewExecutableRule(),
        PrivilegeChangeRule(),
        NewListenerRule(),
        PersistenceRule(),
        AuthAnomalyRule(),
        CriticalChangeRule(),
    ]


def _ensure_migrated() -> None:
    repo_root = Path(__file__).resolve().parent.parent.parent
    ini_path = repo_root / "alembic.ini"
    cfg = Config(str(ini_path))
    command.upgrade(cfg, "head")


def cmd_run(args: argparse.Namespace) -> None:
    _ensure_migrated()
    print(f"DB: {resolve_db_path()}")
    engine = make_engine()

    with Session(engine) as session:
        collectors = _build_collectors()
        rules = _build_rules()
        previous = None

        for i in range(args.cycles):
            print(f"\n--- cycle {i + 1}/{args.cycles} ---")
            t0 = time.monotonic()
            previous, findings = run_cycle(session, collectors, rules, previous)
            elapsed = time.monotonic() - t0
            print(f"  collected+evaluated in {elapsed:.1f}s")

            if previous is not None and i == 0:
                print("  (baseline cycle -- nothing evaluated yet, no prior state to diff against)")
            elif not findings:
                print("  no findings")
            else:
                for f in findings:
                    print(f"  [{f.severity:6s}] {f.rule_id} {f.title}")

            if i < args.cycles - 1:
                time.sleep(args.interval)


def cmd_tui(args: argparse.Namespace) -> None:
    _ensure_migrated()
    from sentry.tui.app import run_tui

    run_tui(cycle_interval=args.interval)


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentry")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Run collection+evaluation cycles, printing findings to the console")
    run_parser.add_argument("--cycles", type=int, default=2, help="number of cycles to run")
    run_parser.add_argument("--interval", type=float, default=5.0, help="seconds between cycles")
    run_parser.set_defaults(func=cmd_run)

    tui_parser = sub.add_parser("tui", help="Launch the interactive dashboard")
    tui_parser.add_argument("--interval", type=float, default=30.0, help="seconds between background collection cycles")
    tui_parser.set_defaults(func=cmd_tui)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
