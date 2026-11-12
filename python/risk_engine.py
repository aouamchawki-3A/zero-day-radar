from collections import deque
import threading

class RiskEngine:
    def __init__(self, max_events=1000):
        self.max_events = max_events
        self.events = deque(maxlen=max_events)
        self.entity_risk_scores = {}  # لتتبع نقاط كل كيان
        self.lock = threading.Lock()

    def add_event(self, event):
        with self.lock:
            # إذا امتلا الطابور، سيتم حذف أقدم حدث تلقائياً بواسطة deque(maxlen)
            # لذلك يجب علينا خصم نقاطه القديمة أولاً من الكيان المرتبط به لتفادي التراكم الوهمي
            if len(self.events) == self.max_events:
                oldest_event = self.events[0]  # الحدث الأقدم الذي سيتم إزالته
                entity = oldest_event.get("source") or oldest_event.get("path")
                old_score = oldest_event.get("risk_score", 0)
               
                if entity and entity in self.entity_risk_scores:
                    self.entity_risk_scores[entity] -= old_score
                    if self.entity_risk_scores[entity] < 0:
                        self.entity_risk_scores[entity] = 0.0

            # إضافة الحدث الجديد وتحديث النقاط
            self.events.append(event)
            entity = event.get("source") or event.get("path")
            score = event.get("risk_score", 0.0)
           
            if entity:
                self.entity_risk_scores[entity] = self.entity_risk_scores.get(entity, 0.0) + score
