import pytest
from python.event_normalizer import normalize_event


@pytest.mark.parametrize("level,score", [
    ("LOW", 10.0),
    ("MEDIUM", 25.0),
    ("HIGH", 50.0),
    ("CRITICAL", 75.0)
])
def test_severity_mapping(level, score):
    result = normalize_event({
        "source": "decoy",
        "event": "open",
        "level": level,
        "detail": "/tmp/decoy.txt"
    })

    assert result["severity_score"] == score


def test_entropy_entity():
    result = normalize_event({
        "source": "scanner",
        "event": "high_entropy",
        "level": "MEDIUM",
        "detail": "/tmp/sample.bin (entropy 8.00)"
    })

    assert result["entity_id"] == "file:/tmp/sample.bin"
    assert result["severity_score"] == 25.0


def test_file_isolation():
    entities = []

    for name in ("a.bin", "b.bin"):
        result = normalize_event({
            "source": "scanner",
            "event": "high_entropy",
            "level": "MEDIUM",
            "detail": f"/tmp/{name} (entropy 8.00)"
        })

        entities.append(result["entity_id"])

    assert entities[0] != entities[1]


def test_listener_entity():
    result = normalize_event({
        "source": "listener",
        "event": "opened",
        "level": "MEDIUM",
        "detail": "tcp/8080"
    })

    assert result["entity_id"] == "listener:tcp/8080"


def test_invalid_events():
    assert normalize_event(None) is None
    assert normalize_event({}) is None

    assert normalize_event({
        "source": "listener",
        "event": "opened",
        "level": "HIGH",
        "detail": "tcp/99999"
    }) is None

    assert normalize_event({
        "source": "scanner",
        "event": "high_entropy",
        "level": "MEDIUM",
        "detail": "invalid"
    }) is None


def test_diagnostic_events():
    assert normalize_event({
        "source": "listener",
        "event": "closed",
        "level": "LOW",
        "detail": "tcp/8080"
    }) is None

    assert normalize_event({
        "source": "decoy",
        "event": "overflow",
        "level": "HIGH",
        "detail": "/tmp/decoy.txt"
    }) is None
