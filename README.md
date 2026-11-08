# Zero-Day Radar v2.0 🛡️

منصة دفاعية خفيفة ومتعددة الطبقات لمراقبة النظام، اكتشاف التهديدات، وإدارة ملفات الطعم (Canary/Decoy Files) اللحظية.

## عمارة النظام (Architecture 2.0)
- **C++ Monitoring Core (`radar_core.cpp`):** مراقبة الأحداث عبر نظام الـ `inotify` وملفات النظام بكفاءة عالية.
- **Rules Engine (`rules.txt`):** قواعد كشف ديناميكية قابلة للتعديل والتحديث مستقلة عن الكود الثابت.
- **Python Analyzer (`analyzer.py` & `risk_engine.py`):** حساب الإنتروبيا (Entropy)، تقييم المخاطر، وربط الأحداث للحد من الإنذارات الكاذبة.
- **GUI Dashboard (`radar_gui.py`):** واجهة رسومية تفاعلية لعرض التنبيهات والسجلات والتقارير لحظياً.

## طريقة التشغيل والتثبيت
1. تشغيل المحرك الأساسي:
   ```bash
   g++ -std=c++11 radar_core.cpp -o radar_core -pthread
   ./radar_core
