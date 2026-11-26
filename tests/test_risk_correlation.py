import pytest
from python.risk_engine import RiskEngine


def test_risk_accumulation():
    engine = RiskEngine(threshold=50.0)

    assert engine.ingest_event({
        "entity_id": "file_a",
        "severity_score": 20
    }) is None

    alert = engine.ingest_event({
        "entity_id": "file_a",
        "severity_score": 30
    })

    assert alert is not None
    assert alert["alert_triggered"] is True
    assert alert["accumulated_score"] == 50


def test_entity_isolation():
    engine = RiskEngine(threshold=50.0)

    for entity in ("file_a", "file_b"):
        assert engine.ingest_event({
            "entity_id": entity,
            "source": "scanner",
            "severity_score": 30
        }) is None

    assert engine.entity_risk_scores == {
        "file_a": 30.0,
        "file_b": 30.0
    }


def test_invalid_risk_scores():
    engine = RiskEngine()

    for score in (-1, float("nan"),
                  float("inf"), "invalid", None):
        with pytest.raises(ValueError):
            engine.ingest_event({
                "entity_id": "file_a",
                "severity_score": score
            })

    assert len(engine.events) == 0


def test_duplicate_alert_prevention():
    engine = RiskEngine(threshold=50.0)

    event = {
        "entity_id": "file_a",
        "severity_score": 60
    }

    assert engine.ingest_event(event) is not None
    assert engine.ingest_event(event) is None
    assert engine.entity_risk_scores["file_a"] == 120
