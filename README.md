# 🛡️ Zero-Day Radar (Reliable Beta)

> **Status:** Active Development / Reliable Beta 
> **Architecture:** Hybrid C++ Core & Python Analysis Engine via Inter-Process Communication (IPC)

---

## 📌 About the Project
**Zero-Day Radar** is a lightweight, performance-oriented security monitoring and threat detection prototype. Designed with a strict engineering philosophy, it avoids unnecessary bloat and focuses on high-speed, reliable system telemetry and local decoy file integrity monitoring.

---

## 🏗️ Architecture & Component Design

The system follows a strict separation of concerns and robust inter-process communication:

1. **C++ Monitoring Core (`radar_core`)**:
   * Built for high performance and low resource consumption.
   * Utilizes Linux `inotify` syscalls to monitor critical decoy/sensitive files (e.g., `/tmp/radar-test-decoy.txt`) in real time.
   * Acts as the parent process managing secure communication via standard pipes.

2. **IPC Bridge (`bridge_worker.py`)**:
   * Uses low-overhead JSON Lines (JSONL) streamed over standard input/output (`stdin`/`stdout`).
   * Strictly separates diagnostic logs (`stderr`) from structured telemetry data (`stdout`).

3. **Risk Engine & Analysis (`risk_engine.py`)**:
   * Sliding window analytics to compute risk scores, categorize threat levels (`HIGH`, `MEDIUM`, `LOW`), and generate security indicators.

4. **Autonomous SOC Dashboard (`dashboard.py`)**:
   * A clean, dark-themed Tkinter-based GUI providing real-time event streaming, KPI tracking (total events and high alerts), and autonomous execution control.

---

## 🚀 Quick Start & Installation

### Prerequisites
* Linux (Ubuntu recommended)
* GCC (supporting C++17)
* Python 3.x

### Compilation & Execution

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ouamchawki-3A/zero-day-radar.git](https://github.com/ouamchawki-3A/zero-day-radar.git)
   cd zero-day-radar
