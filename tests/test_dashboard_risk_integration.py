import json
from unittest.mock import Mock

from dashboard import LiveSOCDashboard
from python.risk_engine import RiskEngine


def create_dashboard():
    dashboard = LiveSOCDashboard.__new__(
        LiveSOCDashboard
    )
    dashboard.total_events = 0
    dashboard.high_alerts = 0
    dashboard.risk_engine = RiskEngine()
    dashboard.log = Mock()
    dashboard.update_kpi = Mock()
    return dashboard


def send_event(dashboard, source, event, level, detail):
    dashboard.process_output(json.dumps({
        "source": source,
        "event": event,
        "level": level,
        "detail": detail
    }))


def test_accumulated_risk():
    dashboard = create_dashboard()

    for _ in range(2):
        send_event(
            dashboard, "scanner", "high_entropy",
            "MEDIUM", "/tmp/a.bin (entropy 8.00)"
        )

    assert dashboard.total_events == 2
    assert dashboard.high_alerts == 1

    message, level = dashboard.log.call_args.args
    assert "RISK CORRELATION ALERT" in message
    assert level == "HIGH"


def test_entity_isolation():
    dashboard = create_dashboard()

    for name in ("a.bin", "b.bin"):
        send_event(
            dashboard, "scanner", "high_entropy",
            "MEDIUM", f"/tmp/{name} (entropy 8.00)"
        )

    assert dashboard.total_events == 2
    assert dashboard.high_alerts == 0


def test_high_event_counts_once():
    dashboard = create_dashboard()

    send_event(
        dashboard, "decoy", "open",
        "HIGH", "/tmp/decoy.txt"
    )

    assert dashboard.total_events == 1
    assert dashboard.high_alerts == 1
    dashboard.update_kpi.assert_called_once_with()


def test_duplicate_correlation_alert():
    dashboard = create_dashboard()

    for _ in range(3):
        send_event(
            dashboard, "scanner", "high_entropy",
            "MEDIUM", "/tmp/a.bin (entropy 8.00)"
        )

    assert dashboard.total_events == 3
    assert dashboard.high_alerts == 1

    alerts = [
        call for call in dashboard.log.call_args_list
        if "RISK CORRELATION ALERT" in call.args[0]
    ]

    assert len(alerts) == 1


def test_critical_event():
    dashboard = create_dashboard()

    send_event(
        dashboard, "decoy", "modify",
        "CRITICAL", "/tmp/decoy.txt"
    )

    assert dashboard.total_events == 1
    assert dashboard.high_alerts == 1
    assert dashboard.log.call_args.args[1] == "HIGH"
