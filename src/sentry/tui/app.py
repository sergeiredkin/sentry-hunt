"""Textual TUI: health dashboard + alert drill-down (spec §13 task 10).

Reads the same SQLite state any other UI would (spec §1's "UI-agnostic
engine" principle) -- the TUI itself only knows about AlertRow/observation
counts, not collectors or rules, except to drive a background collection
worker for this stand-in (see run_collection_loop). A real continuous-mode
scheduler (spec §13 task 8, not yet built) will eventually replace that ad
hoc loop; at that point this app becomes a pure read-only consumer.

Acknowledge/Mute both write a `suppressions` row today, but always with
scope="exact_event" -- spec §8's richer per-rule default scope (path_hash
for rules 1/6) is deferred until task 7 actually builds suppression
*matching*, since writing that encoding now without the matching logic to
consume it risks getting the format wrong and having to redo it.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from rich.text import Text
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Label, Static

from sentry.engine.pipeline import run_cycle
from sentry.storage.db import make_engine, resolve_db_path
from sentry.suppression.scopes import path_hash_value
from sentry.storage.models import (
    AlertRow,
    AuthEventRow,
    CollectorHealthRow,
    FileIntegrityRow,
    NetworkObservationRow,
    PersistenceEntryRow,
    ProcessObservationRow,
    SuppressionRow,
    UserAccountRow,
)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_COUNTED_MODELS = (
    ProcessObservationRow,
    NetworkObservationRow,
    UserAccountRow,
    PersistenceEntryRow,
    FileIntegrityRow,
    AuthEventRow,
)


class EvidenceScreen(ModalScreen[None]):
    """Drill-down: full evidence for one alert, plus Acknowledge/Mute."""

    DEFAULT_CSS = """
    EvidenceScreen { align: center middle; }
    #evidence-dialog { width: 90%; height: 85%; border: round white; background: $panel; padding: 1 2; }
    #evidence-body { height: 1fr; margin-top: 1; }
    #evidence-buttons { height: auto; margin-top: 1; }
    """

    def __init__(self, alert_id: int):
        super().__init__()
        self.alert_id = alert_id

    def compose(self) -> ComposeResult:
        with Vertical(id="evidence-dialog"):
            yield Label("", id="evidence-title")
            yield VerticalScroll(Static("", id="evidence-body"))
            with Horizontal(id="evidence-buttons"):
                yield Button("Acknowledge", id="ack-btn", variant="primary")
                yield Button("Mute", id="mute-btn", variant="warning")
                yield Button("Close", id="close-btn")

    def on_mount(self) -> None:
        app: SentryTUI = self.app  # type: ignore[assignment]
        with Session(app.engine) as session:
            alert = session.get(AlertRow, self.alert_id)
            if alert is None:
                self.dismiss()
                return
            # Text(...), not an f-string, for both of these: alert.title
            # and the evidence values below can contain attacker-chosen
            # content (e.g. a crafted exe_path or cmdline -- Linux allows
            # almost any byte in a filename). Passing a plain str to
            # .update() gets parsed as Rich console markup by default, so
            # a filename like "[bold red]FAKE[/]" could alter how the
            # alert renders. Text() takes the string literally instead.
            title_text = Text(f"[{alert.severity}] {alert.rule_id} -- {alert.title}  (status: {alert.status})")
            self.query_one("#evidence-title", Label).update(title_text)
            evidence = json.loads(alert.evidence_json)
            pretty = "\n".join(f"{k}: {v}" for k, v in evidence.items())
            self.query_one("#evidence-body", Static).update(Text(pretty) if pretty else "(no evidence fields)")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app: SentryTUI = self.app  # type: ignore[assignment]
        if event.button.id == "ack-btn":
            app.acknowledge_alert(self.alert_id)
            self.dismiss()
        elif event.button.id == "mute-btn":
            app.mute_alert(self.alert_id)
            self.dismiss()
        else:
            self.dismiss()


class SentryTUI(App[None]):
    TITLE = "sentry"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh now"),
    ]
    # Enter is deliberately not bound here: DataTable's own default Enter
    # binding (row selection -> RowSelected message) fires first and would
    # swallow an App-level "enter" binding before it's ever seen. Drill-down
    # is wired to that RowSelected message instead (on_data_table_row_selected).

    def __init__(self, cycle_interval: float = 30.0):
        super().__init__()
        self.engine = make_engine(connect_args={"timeout": 30})
        self.cycle_interval = cycle_interval
        self._previous_cycle_time: datetime | None = None
        self._alert_ids_by_row: list[int] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("starting...", id="status")
        yield DataTable(id="alerts-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("ID", "Severity", "Rule", "Title", "Status", "Created")
        table.cursor_type = "row"
        self.refresh_alerts()
        self.run_collection_loop()

    @work(thread=True, exclusive=True)
    def run_collection_loop(self) -> None:
        # Deferred import: cli.py builds the standard collector/rule set;
        # importing here (not at module load) avoids a cli<->tui import
        # cycle since cli.py also launches this app.
        from sentry.cli import _build_collectors, _build_rules
        from sentry.config.loader import load_config

        config = load_config()
        collectors, hash_cache = _build_collectors(config)
        rules = _build_rules(config)
        while True:
            self._run_one_collection_cycle(collectors, rules, hash_cache)
            time.sleep(self.cycle_interval)

    def _run_one_collection_cycle(self, collectors, rules, hash_cache) -> None:
        """One iteration of the background loop, split out so it's directly
        testable and so a single bad cycle can't kill the worker forever.
        Without this try/except, any unhandled exception here (SQLite lock
        contention between this thread and a foreground Acknowledge/Mute
        write, or anything else) would propagate out of the @work thread
        and silently end run_collection_loop's `while True` for the rest
        of the session -- the dashboard would go stale forever with no
        visible error and no restart."""
        try:
            with Session(self.engine) as session:
                self._previous_cycle_time, _findings = run_cycle(
                    session,
                    collectors,
                    rules,
                    self._previous_cycle_time,
                    hash_cache=hash_cache,
                    config=config,
                )
            self.call_from_thread(self.refresh_alerts)
        except Exception:
            import logging

            logging.getLogger(__name__).exception("collection cycle failed; will retry next interval")

    def refresh_alerts(self) -> None:
        with Session(self.engine) as session:
            counts = {
                model.__tablename__: session.execute(select(func.count()).select_from(model)).scalar_one()
                for model in _COUNTED_MODELS
            }
            failed_collectors = session.execute(
                select(func.count()).select_from(CollectorHealthRow).where(CollectorHealthRow.status == "failed")
            ).scalar_one()
            alerts = list(
                session.execute(select(AlertRow).order_by(AlertRow.created_at.desc()).limit(200)).scalars()
            )

        active_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in alerts:
            if a.status == "active":
                active_counts[a.severity] = active_counts.get(a.severity, 0) + 1

        status = (
            f"DB: {resolve_db_path()}  |  "
            f"processes={counts['process_observations']} network={counts['network_observations']} "
            f"users={counts['users_groups']} persistence={counts['persistence_entries']} "
            f"files={counts['file_integrity']} auth_events={counts['auth_events']}  |  "
            f"active: HIGH={active_counts['HIGH']} MEDIUM={active_counts['MEDIUM']} LOW={active_counts['LOW']}  "
            f"collector_failures={failed_collectors}"
        )
        self.query_one("#status", Static).update(status)

        table = self.query_one(DataTable)
        table.clear()
        self._alert_ids_by_row = []
        for a in sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), -a.id)):
            # a.title can contain attacker-chosen content (see EvidenceScreen's
            # on_mount comment) -- Text() so it's never parsed as markup.
            table.add_row(
                str(a.id), a.severity, a.rule_id, Text(a.title), a.status, a.created_at.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._alert_ids_by_row.append(a.id)

    def action_refresh(self) -> None:
        self.refresh_alerts()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Fires when Enter is pressed (or a row clicked) on the alerts
        table -- DataTable's own built-in binding, not an App-level one."""
        row_index = event.cursor_row
        if row_index is None or row_index >= len(self._alert_ids_by_row):
            return
        alert_id = self._alert_ids_by_row[row_index]
        self.push_screen(EvidenceScreen(alert_id))

    def acknowledge_alert(self, alert_id: int) -> None:
        self._resolve_alert(alert_id, status="acknowledged", reason="acknowledged via TUI", mute=False)
        self.refresh_alerts()

    def mute_alert(self, alert_id: int) -> None:
        self._resolve_alert(alert_id, status="muted", reason="muted via TUI", mute=True)
        self.refresh_alerts()

    def _resolve_alert(self, alert_id: int, status: str, reason: str, mute: bool = False) -> None:
        """The pure DB-mutation half of acknowledge/mute, kept separate
        from refresh_alerts() so it's callable/testable without a mounted
        widget tree (refresh_alerts() touches live widgets via query_one)."""
        with Session(self.engine) as session:
            alert = session.get(AlertRow, alert_id)
            if alert is None:
                return
            alert.status = status
            evidence = json.loads(alert.evidence_json)
            scope = "exact_event"
            match_value = alert.dedup_key
            if mute and alert.rule_id in {"R1", "R6"}:
                pairs = []
                if evidence.get("exe_path"):
                    pairs.append((evidence.get("exe_path"), evidence.get("sha256")))
                if evidence.get("path"):
                    pairs.append((evidence.get("path"), evidence.get("new_sha256", evidence.get("sha256"))))
                if pairs and pairs[0][0]:
                    scope = "path_hash"
                    match_value = path_hash_value(pairs[0][0], pairs[0][1])
            session.add(
                SuppressionRow(
                    rule_id=alert.rule_id,
                    scope=scope,
                    match_value=match_value,
                    reason=reason,
                    created_at=datetime.now(timezone.utc),
                    expires_at=None,
                    created_by="user",
                )
            )
            session.commit()


def run_tui(cycle_interval: float = 30.0) -> None:
    SentryTUI(cycle_interval=cycle_interval).run()
