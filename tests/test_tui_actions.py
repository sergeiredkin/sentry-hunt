from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session
from textual.widgets import DataTable

from sentry.storage.models import AlertRow, Base, SuppressionRow
from sentry.tui.app import SentryTUI


def _make_app(tmp_path, monkeypatch) -> SentryTUI:
    monkeypatch.setenv("SENTRY_DB_PATH", str(tmp_path / "state.db"))
    app = SentryTUI()
    Base.metadata.create_all(app.engine)
    return app


def _seed_alert(app: SentryTUI, dedup_key="dk1", rule_id="R1", status="active") -> int:
    with Session(app.engine) as session:
        alert = AlertRow(
            rule_id=rule_id,
            severity="LOW",
            created_at=datetime.now(timezone.utc),
            status=status,
            title="t",
            evidence_json="{}",
            dedup_key=dedup_key,
        )
        session.add(alert)
        session.commit()
        return alert.id


def test_resolve_alert_acknowledged_sets_status_and_writes_suppression(tmp_path, monkeypatch):
    app = _make_app(tmp_path, monkeypatch)
    alert_id = _seed_alert(app)

    app._resolve_alert(alert_id, status="acknowledged", reason="acknowledged via TUI")

    with Session(app.engine) as session:
        alert = session.get(AlertRow, alert_id)
        assert alert.status == "acknowledged"
        suppressions = session.execute(select(SuppressionRow)).scalars().all()
        assert len(suppressions) == 1
        assert suppressions[0].scope == "exact_event"
        assert suppressions[0].match_value == "dk1"
        assert suppressions[0].rule_id == "R1"
        assert suppressions[0].created_by == "user"


def test_resolve_alert_muted_sets_status(tmp_path, monkeypatch):
    app = _make_app(tmp_path, monkeypatch)
    alert_id = _seed_alert(app)

    app._resolve_alert(alert_id, status="muted", reason="muted via TUI")

    with Session(app.engine) as session:
        alert = session.get(AlertRow, alert_id)
        assert alert.status == "muted"


def test_resolve_alert_is_noop_for_missing_alert(tmp_path, monkeypatch):
    app = _make_app(tmp_path, monkeypatch)

    app._resolve_alert(99999, status="acknowledged", reason="x")  # must not raise

    with Session(app.engine) as session:
        assert session.execute(select(AlertRow)).scalars().all() == []
        assert session.execute(select(SuppressionRow)).scalars().all() == []


def test_one_collection_cycle_survives_an_exception(tmp_path, monkeypatch):
    """Security-review fix: without this, any exception in a cycle (e.g.
    SQLite lock contention with a foreground Acknowledge/Mute write) would
    propagate out of the @work thread and permanently end
    run_collection_loop's `while True` for the rest of the session."""
    app = _make_app(tmp_path, monkeypatch)

    def raise_run_cycle(*a, **k):
        raise RuntimeError("simulated cycle failure")

    monkeypatch.setattr("sentry.tui.app.run_cycle", raise_run_cycle)

    app._run_one_collection_cycle([], [], None)  # must not raise

    assert app._previous_cycle_time is None  # never advanced past the failure


def test_alert_title_markup_is_not_interpreted_in_table(tmp_path, monkeypatch):
    """Security-review fix: an alert title can contain attacker-chosen
    content (e.g. a crafted exe_path or cmdline). Static/DataTable parse
    plain strings as Rich console markup by default, so an unescaped
    title like "[bold red]FAKE[/bold red] ..." could alter how the alert
    visually renders. Wrapping in rich.text.Text (see refresh_alerts())
    must make Textual treat it as literal text instead."""
    app = _make_app(tmp_path, monkeypatch)
    app.run_collection_loop = lambda: None  # avoid the real background worker in this headless test
    malicious_title = "[bold red]INJECTED FAKE ALERT[/bold red] New executable observed: /tmp/x"
    _seed_alert(app, dedup_key="dk-markup", status="active")
    with Session(app.engine) as session:
        alert = session.execute(select(AlertRow).where(AlertRow.dedup_key == "dk-markup")).scalar_one()
        alert.title = malicious_title
        session.commit()

    async def run_check():
        async with app.run_test() as pilot:
            await pilot.pause()
            app.refresh_alerts()
            await pilot.pause()
            table = app.query_one(DataTable)
            row_key = list(table.rows.keys())[0]
            title_column_key = table.ordered_columns[2].key  # Severity, Rule, Title, Status, Created
            cell = table.get_cell(row_key, title_column_key)
            assert cell.plain == malicious_title

    asyncio.run(run_check())
