import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from python.risk_engine import RiskEngine


def test_risk_engine_threshold():
    engine = RiskEngine(window_size_seconds=60)
    alert = engine.ingest_event({
        "source_ip": "192.168.1.100",
        "severity_score": 60.0
    })
    assert alert is not None
    assert alert["alert_triggered"] is True
    assert alert["entity_id"] == "192.168.1.100"
    assert alert["accumulated_score"] >= 50.0
    print("✅ test_risk_engine_threshold")


def test_event_expiry():
    engine = RiskEngine(window_size_seconds=1, threshold=50.0)
    engine.ingest_event({"source_ip": "10.0.0.1", "severity_score": 40.0})
    time.sleep(1.1)
    alert = engine.ingest_event({"source_ip": "10.0.0.1", "severity_score": 40.0})
    assert alert is None
    print("✅ test_event_expiry")


def test_max_events_not_exceeded():
    engine = RiskEngine(window_size_seconds=60, threshold=99999, max_events=10)
    for i in range(20):
        engine.ingest_event({"source_ip": f"10.0.0.{i % 5}", "severity_score": 1.0})
    with engine.lock:
        assert len(engine.events) <= 10
    print("✅ test_max_events_not_exceeded")


def test_alert_re_trigger_after_drop():
    engine = RiskEngine(window_size_seconds=1, threshold=50.0)
    ip = "10.0.0.99"
    alert1 = engine.ingest_event({"source_ip": ip, "severity_score": 60.0})
    assert alert1 is not None
    time.sleep(1.1)
    alert2 = engine.ingest_event({"source_ip": ip, "severity_score": 60.0})
    assert alert2 is not None
    print("✅ test_alert_re_trigger_after_drop")


if __name__ == "__main__":
    test_risk_engine_threshold()
    test_event_expiry()
    test_max_events_not_exceeded()
    test_alert_re_trigger_after_drop()
    print("\n🎉 جميع الاختبارات نجحت!") 
