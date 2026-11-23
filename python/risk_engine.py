from collections import deque
import threading
import time
import math


class RiskEngine:
    def __init__(
        self,
        window_size_seconds=60,
        threshold=50.0,
        max_events=1000
    ):
        if window_size_seconds <= 0:
            raise ValueError("window_size_seconds must be positive")

        if not math.isfinite(threshold) or threshold <= 0:
            raise ValueError("threshold must be positive and finite")

        if max_events <= 0:
            raise ValueError("max_events must be positive")

        self.window_size_seconds = window_size_seconds
        self.threshold = float(threshold)
        self.max_events = max_events

        self.events = deque()
        self.entity_risk_scores = {}
        self.alerted_entities = set()

        self.lock = threading.Lock()

    def _remove_event(self, event):
        entity = event["entity_id"]
        score = event["risk_score"]
        remaining = max(0.0, self.entity_risk_scores.get(entity, 0.0) - score)
        if remaining <= 1e-9:
            self.entity_risk_scores.pop(entity, None)
            self.alerted_entities.discard(entity)
        else:
            self.entity_risk_scores[entity] = remaining
            if remaining < self.threshold:
                self.alerted_entities.discard(entity)

    def _cleanup(self, now):
        while self.events:
            oldest = self.events[0]

            if now - oldest["timestamp"] <= self.window_size_seconds:
                break

            self._remove_event(self.events.popleft())

    def ingest_event(self, event):
        entity = (
            event.get("source_ip")
            or event.get("source")
            or event.get("path")
        )

        if not entity:
            raise ValueError("Event must contain an entity identifier")
        entity = str(entity)
        score = event.get(
            "severity_score",
            event.get("risk_score", 0.0)
        )

        try:
            score = float(score)
        except (TypeError, ValueError):
            raise ValueError("Invalid risk score")

        if not math.isfinite(score) or score < 0:
            raise ValueError("Risk score must be finite and non-negative")

        now = time.monotonic()

        with self.lock:
            self._cleanup(now)

            while len(self.events) >= self.max_events:
                self._remove_event(self.events.popleft())

            stored_event = {
                "entity_id": str(entity),
                "risk_score": score,
                "timestamp": now,
                "event": dict(event)
            }

            self.events.append(stored_event)

            self.entity_risk_scores[entity] = (
                self.entity_risk_scores.get(entity, 0.0) + score
            )

            accumulated = self.entity_risk_scores[entity]

            triggered = (
                accumulated >= self.threshold
                and entity not in self.alerted_entities
            )

            if not triggered:
                return None

            self.alerted_entities.add(entity)

            return {
                "alert_triggered": True,
                "entity_id": entity,
                "accumulated_score": accumulated,
                "threshold": self.threshold,
                "window_size_seconds": self.window_size_seconds
            }

    def add_event(self, event):
        return self.ingest_event(event)
