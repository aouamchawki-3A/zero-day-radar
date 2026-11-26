import re
SEVERITY_SCORES = {
    "LOW": 10.0,
    "MEDIUM": 25.0,
    "HIGH": 50.0,
    "CRITICAL": 75.0
}


def normalize_event(data):
    if not isinstance(data, dict):
        return None

    source = data.get("source")
    event = data.get("event")
    level = data.get("level")
    detail = data.get("detail")

    if not all(isinstance(v, str) for v in
               (source, event, level, detail)):
        return None

    if not detail.strip():
        return None

    level = level.upper()
    score = SEVERITY_SCORES.get(level)

    if score is None:
        return None

    if source == "scanner" and event == "high_entropy":
        match = re.fullmatch(
            r"(.+) \(entropy (?:[0-7]\.[0-9]{2}|8\.00)\)",
            detail,
            flags=re.DOTALL
        )

        if not match:
            return None

        entity = "file:" + match.group(1)

    elif source == "decoy":
        if event not in (
            "open", "access", "modify", "attrib",
            "delete", "create", "moved_from", "moved_to"
        ):
            return None

        entity = "file:" + detail

    elif source == "listener" and event == "opened":
        match = re.fullmatch(r"tcp/([0-9]{1,5})", detail)

        if not match:
            return None

        port = int(match.group(1))

        if not 1 <= port <= 65535:
            return None

        entity = f"listener:tcp/{port}"

    else:
        return None

    return {
        "entity_id": entity,
        "source": source,
        "event": event,
        "level": level,
        "severity_score": score
    }
