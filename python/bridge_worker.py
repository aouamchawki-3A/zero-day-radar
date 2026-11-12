import sys
import json
from datetime import datetime, timezone


def analyze_event(event):
    event_id = event.get("event_id")
    event_type = event.get("event_type")
    path = event.get("path")

    if not isinstance(event_id, str) or not event_id:
        raise ValueError("Missing event_id")

    if not isinstance(event_type, str):
        raise ValueError("Invalid event_type")

    if not isinstance(path, str) or not path:
        raise ValueError("Missing event path")

    # Initial defensive rules for the monitored decoy.
    rules = {
        "decoy_access": {
            "score": 80,
            "level": "HIGH",
            "indicator": "MONITORED_DECOY_ACCESSED"
        },
        "decoy_modified": {
            "score": 90,
            "level": "HIGH",
            "indicator": "MONITORED_DECOY_MODIFIED"
        },
        "decoy_created": {
            "score": 40,
            "level": "MEDIUM",
            "indicator": "MONITORED_DECOY_CREATED"
        },
        "decoy_deleted": {
            "score": 90,
            "level": "HIGH",
            "indicator": "MONITORED_DECOY_DELETED"
        }
    }

    rule = rules.get(event_type)

    if rule is None:
        score = 0
        level = "LOW"
        indicators = []
    else:
        score = rule["score"]
        level = rule["level"]
        indicators = [rule["indicator"]]

    return {
        "schema_version": 1,
        "event_id": event_id,
        "event_type": event_type,
        "path": path,
        "risk_score": score,
        "level": level,
        "indicators": indicators,
        "analysis_source": "python_rule_engine",
        "analyzed_at": datetime.now(
            timezone.utc
        ).isoformat()
    }


def main():
    for line in sys.stdin:
        try:
            event = json.loads(line)

            if not isinstance(event, dict):
                raise ValueError("Event must be a JSON object")

            result = analyze_event(event)

        except Exception as exc:
            result = {
                "schema_version": 1,
                "event_id": None,
                "level": "ERROR",
                "error": str(exc)
            }

        print(
            json.dumps(result, ensure_ascii=False),
            flush=True
        )


if __name__ == "__main__":
    main()
