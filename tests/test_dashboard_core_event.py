from unittest.mock import Mock

from dashboard import LiveSOCDashboard


def test_high_core_event_counts_once():
    dashboard = LiveSOCDashboard.__new__(LiveSOCDashboard)
    dashboard.total_events = 0
    dashboard.high_alerts = 0
    dashboard.log = Mock()
    dashboard.update_kpi = Mock()

    line = '{"source": "decoy", "event": "open", "level": "HIGH"}'
    dashboard.process_output(line)

    assert (dashboard.total_events, dashboard.high_alerts) == (1, 1)
    dashboard.update_kpi.assert_called_once_with()
