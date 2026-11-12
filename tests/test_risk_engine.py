import sys
import os

# إضافة مجلد المشروع الرئيسي لمسار البحث لضمان استيراد الملفات بسلاسة
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from python.risk_engine import RiskEngine

def test_risk_engine_threshold():
    # تهيئة المحرك بنافذة زمنية 60 ثانية
    engine = RiskEngine(window_size_seconds=60)

    # محاكاة حدث أمني بنقاط خطورة عالية
    event = {
        "source_ip": "192.168.1.100",
        "severity_score": 60.0
    }

    alert = engine.ingest_event(event)

    # التحقق من إطلاق التنبيه فور تجاوز عتبة 50 نقطة
    assert alert is not None, "فشل: لم يتم إطلاق تنبيه رغم تجاوز العتبة"
    assert alert["alert_triggered"] is True
    assert alert["entity_id"] == "192.168.1.100"
    assert alert["accumulated_score"] >= 50.0

    print("✅ نجح اختبار محرك المخاطر (Risk Engine Test Passed Successfully)!")

if __name__ == "__main__":
    test_risk_engine_threshold()
