from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

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
