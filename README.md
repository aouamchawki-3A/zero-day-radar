 HEAD
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

# Zero-Day Radar 🛡️

A hybrid network monitoring and threat detection framework combining high-performance C++ core engines with flexible Python analytical scripts.

## 📌 Features
- **High-Performance Core Engine (C++):** Real-time network packet capture and low-level process monitoring.
- **Python Analytical Engine:** Parses telemetry data, evaluates logs, and integrates with threat intelligence feeds.
- **Customizable Rule Set:** Define custom detection signatures and system parameters via `rules.txt` and `radar.conf`.

## 📁 Repository Structure
- `radar_core.cpp` / `radar_core` - Core network monitoring engine.
- `radar_gui.cpp` / `radar_gui` - User interface dashboard.
- `zeroday_radar.py` - Analytical parsing and alert engine.
- `rules.txt` - Threat matching rules.
- `radar.conf` - Configuration parameters.

## 🚀 Quick Start

### Prerequisites
- GCC / G++ compiler
- Python 3.x
- `pcap` development libraries (`libpcap-dev`)

### Compilation & Execution
1. Compile the C++ modules:
   ```bash
   g++ -O2 radar_core.cpp -o radar_core -lpcap
   g++ -O2 radar_gui.cpp -o radar_gui
 d431ba8c36a597cced4091d209fc1f7fd0fde603
