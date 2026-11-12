import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import queue
import json
import os
import sys
from pathlib import Path
from datetime import datetime


class LiveSOCDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Day Radar | Security Operations Center")
        self.root.geometry("1150x740")
        self.root.minsize(900, 600)
        self.root.configure(bg="#0f172a")

        # Application state
        self.total_events = 0
        self.high_alerts = 0
        self.is_running = False

        self.stop_event = threading.Event()
        self.event_queue = queue.Queue()

        self.process = None
        self.process_lock = threading.Lock()

        self.core_path = (
            Path(__file__).resolve().parent / "radar_core"
        )

        self._build_interface()

        self.log(
            "Dashboard initialized successfully.",
            "SUCCESS"
        )

        self.root.after(100, self.process_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # --------------------------------------------------
    # UI
    # --------------------------------------------------

    def _build_interface(self):
        header = tk.Frame(
            self.root,
            bg="#1e293b",
            height=65
        )
        header.pack(fill=tk.X, padx=12, pady=12)
        header.pack_propagate(False)

        tk.Label(
            header,
            text="ZERO-DAY RADAR",
            font=("Segoe UI", 17, "bold"),
            bg="#1e293b",
            fg="#38bdf8"
        ).pack(side=tk.LEFT, padx=18, pady=12)

        tk.Label(
            header,
            text="SECURITY OPERATIONS CENTER",
            font=("Segoe UI", 9, "bold"),
            bg="#1e293b",
            fg="#94a3b8"
        ).pack(side=tk.LEFT, padx=5, pady=18)

        self.status_badge = tk.Label(
            header,
            text="● OFFLINE",
            font=("Segoe UI", 10, "bold"),
            bg="#334155",
            fg="#facc15",
            padx=12,
            pady=7
        )
        self.status_badge.pack(side=tk.RIGHT, padx=15)

        # KPI section
        kpi_frame = tk.Frame(
            self.root,
            bg="#0f172a"
        )
        kpi_frame.pack(fill=tk.X, padx=10, pady=5)

        self.card_events = self.create_kpi_card(
            kpi_frame,
            "TOTAL EVENTS",
            "0",
            "#38bdf8"
        )

        self.card_alerts = self.create_kpi_card(
            kpi_frame,
            "HIGH ALERTS",
            "0",
            "#ef4444"
        )

        self.card_status = self.create_kpi_card(
            kpi_frame,
            "ENGINE STATUS",
            "READY",
            "#10b981"
        )

        # Main body
        body = tk.Frame(
            self.root,
            bg="#0f172a"
        )
        body.pack(
            fill=tk.BOTH,
            expand=True,
            padx=12,
            pady=12
        )

        # Event stream
        log_container = tk.LabelFrame(
            body,
            text=" LIVE EVENT STREAM ",
            font=("Segoe UI", 10, "bold"),
            bg="#0f172a",
            fg="#94a3b8",
            bd=1
        )
        log_container.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=(0, 12)
        )

        self.log_area = scrolledtext.ScrolledText(
            log_container,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#020617",
            fg="#cbd5e1",
            insertbackground="white",
            bd=0,
            padx=10,
            pady=10
        )
        self.log_area.pack(
            fill=tk.BOTH,
            expand=True,
            padx=8,
            pady=8
        )

        self.log_area.tag_config(
            "INFO",
            foreground="#cbd5e1"
        )
        self.log_area.tag_config(
            "SUCCESS",
            foreground="#34d399"
        )
        self.log_area.tag_config(
            "WARNING",
            foreground="#facc15"
        )
        self.log_area.tag_config(
            "HIGH",
            foreground="#f87171"
        )
        self.log_area.tag_config(
            "ERROR",
            foreground="#fb7185"
        )

        # Control panel
        controls = tk.Frame(
            body,
            width=230,
            bg="#1e293b"
        )
        controls.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        controls.pack_propagate(False)

        tk.Label(
            controls,
            text="CONTROL CENTER",
            font=("Segoe UI", 12, "bold"),
            bg="#1e293b",
            fg="#f8fafc"
        ).pack(pady=20)

        button_style = {
            "font": ("Segoe UI", 10, "bold"),
            "relief": tk.FLAT,
            "cursor": "hand2",
            "pady": 10
        }

        self.btn_start = tk.Button(
            controls,
            text="▶ START MONITORING",
            bg="#059669",
            fg="white",
            command=self.start_monitoring,
            **button_style
        )
        self.btn_start.pack(
            fill=tk.X,
            padx=15,
            pady=8
        )

        self.btn_stop = tk.Button(
            controls,
            text="■ STOP MONITORING",
            bg="#475569",
            fg="white",
            state=tk.DISABLED,
            command=self.stop_monitoring,
            **button_style
        )
        self.btn_stop.pack(
            fill=tk.X,
            padx=15,
            pady=8
        )

        self.btn_clear = tk.Button(
            controls,
            text="CLEAR LOGS",
            bg="#334155",
            fg="white",
            command=self.clear_logs,
            **button_style
        )
        self.btn_clear.pack(
            fill=tk.X,
            padx=15,
            pady=8
        )

        # System information
        tk.Label(
            controls,
            text="SYSTEM INFORMATION",
            font=("Segoe UI", 10, "bold"),
            bg="#1e293b",
            fg="#38bdf8"
        ).pack(pady=(35, 10))

        self.system_info = tk.Label(
            controls,
            text=f"Python: {sys.version_info.major}."
                 f"{sys.version_info.minor}\n"
                 f"Platform: {sys.platform}",
            font=("Consolas", 9),
            bg="#1e293b",
            fg="#94a3b8",
            justify=tk.LEFT
        )
        self.system_info.pack(padx=15, anchor="w")

        # Footer
        footer = tk.Label(
            self.root,
            text="ZERO-DAY RADAR | DEFENSIVE MONITORING SYSTEM",
            font=("Segoe UI", 8),
            bg="#0f172a",
            fg="#64748b"
        )
        footer.pack(pady=5)

    # --------------------------------------------------
    # KPI cards
    # --------------------------------------------------

    def create_kpi_card(
        self,
        parent,
        title,
        initial_value,
        color
    ):
        card = tk.Frame(
            parent,
            bg="#1e293b",
            bd=1,
            relief=tk.SOLID,
            padx=15,
            pady=12
        )
        card.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=5
        )

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 9, "bold"),
            bg="#1e293b",
            fg="#94a3b8"
        ).pack(anchor="w")

        value = tk.Label(
            card,
            text=initial_value,
            font=("Segoe UI", 19, "bold"),
            bg="#1e293b",
            fg=color
        )
        value.pack(anchor="w", pady=(5, 0))

        return value

    def update_kpi(self):
        self.card_events.config(
            text=str(self.total_events)
        )
        self.card_alerts.config(
            text=str(self.high_alerts)
        )

    # --------------------------------------------------
    # Logging
    # --------------------------------------------------

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        prefixes = {
            "INFO": "[INFO]",
            "SUCCESS": "[SUCCESS]",
            "WARNING": "[WARNING]",
            "HIGH": "[HIGH ALERT]",
            "ERROR": "[ERROR]"
        }

        prefix = prefixes.get(level, "[INFO]")

        self.log_area.insert(
            tk.END,
            f"{timestamp} {prefix} {message}\n",
            level
        )

        self.log_area.see(tk.END)

        # Keep the log widget bounded in size.
        line_count = int(
            self.log_area.index("end-1c").split(".")[0]
        )

        if line_count > 5000:
            self.log_area.delete("1.0", "1000.0")

    def clear_logs(self):
        self.log_area.delete("1.0", tk.END)
        self.log("Event log cleared.", "SUCCESS")

    # --------------------------------------------------
    # Process management
    # --------------------------------------------------

    def start_monitoring(self):
        if self.is_running:
            return

        if not self.core_path.is_file():
            self.log(
                f"Core executable not found: {self.core_path}",
                "ERROR"
            )
            return

        if not os.access(self.core_path, os.X_OK):
            self.log(
                "Core executable is not executable. "
                "Check its permissions.",
                "ERROR"
            )
            return

        self.stop_event.clear()
        self.is_running = True

        self.btn_start.config(
            state=tk.DISABLED,
            bg="#334155"
        )

        self.btn_stop.config(
            state=tk.NORMAL,
            bg="#dc2626"
        )

        self.status_badge.config(
            text="● STARTING",
            bg="#854d0e",
            fg="#fef08a"
        )

        self.card_status.config(
            text="STARTING",
            fg="#facc15"
        )

        self.log(
            "Starting C++ monitoring engine...",
            "SUCCESS"
        )

        threading.Thread(
            target=self.run_core,
            daemon=True
        ).start()

    def run_core(self):
        process = None

        try:
            process = subprocess.Popen(
                [str(self.core_path)],
                cwd=str(self.core_path.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1
            )

            with self.process_lock:
                self.process = process

            self.event_queue.put(
                ("status", "RUNNING")
            )

            # If stop was requested before the process
            # finished starting, terminate it immediately.
            if self.stop_event.is_set():
                process.terminate()

            if process.stdout is not None:
                for line in process.stdout:
                    if self.stop_event.is_set():
                        break

                    line = line.strip()

                    if line:
                        self.event_queue.put(
                            ("output", line)
                        )

            if self.stop_event.is_set() and process.poll() is None:
                process.terminate()

            try:
                return_code = process.wait(timeout=3)

            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait()

            self.event_queue.put(
                ("exit", return_code)
            )

        except Exception as exc:
            self.event_queue.put(
                ("error", str(exc))
            )

        finally:
            if process is not None:
                with self.process_lock:
                    if self.process is process:
                        self.process = None

    # --------------------------------------------------
    # Event processing
    # --------------------------------------------------

    def process_output(self, line):
        try:
            data = json.loads(line)

        except json.JSONDecodeError:
            # Plain text output is diagnostic information,
            # not automatically a security event.
            self.log(line, "INFO")
            return

        if not isinstance(data, dict):
            self.log(
                "Received JSON data with an invalid structure.",
                "WARNING"
            )
            return

        # Count only structured event or analysis records.
        is_event = any(
            key in data
            for key in (
                "event_id",
                "event_type",
                "schema_version"
            )
        )

        if not is_event:
            self.log(
                json.dumps(data, ensure_ascii=False),
                "INFO"
            )
            return

        self.total_events += 1

        level = str(
            data.get("level", "LOW")
        ).upper()

        try:
            risk_score = float(
                data.get("risk_score", 0)
            )
        except (ValueError, TypeError):
            risk_score = 0

        if level == "HIGH":
            self.high_alerts += 1
            log_level = "HIGH"

        elif level in ("MEDIUM", "WARNING"):
            log_level = "WARNING"

        else:
            log_level = "SUCCESS"

        event_id = data.get(
            "event_id",
            "N/A"
        )

        event_type = data.get(
            "event_type",
            "analysis_result"
        )

        message = (
            f"Event: {event_type} | "
            f"ID: {event_id} | "
            f"Risk: {risk_score:g} | "
            f"Level: {level}"
        )

        indicators = data.get("indicators", [])

        if isinstance(indicators, list) and indicators:
            message += (
                " | Indicators: "
                + ", ".join(map(str, indicators))
            )

        self.log(message, log_level)
        self.update_kpi()

    # --------------------------------------------------
    # Main-thread event queue
    # --------------------------------------------------

    def process_queue(self):
        try:
            while True:
                event_type, payload = (
                    self.event_queue.get_nowait()
                )

                if event_type == "output":
                    self.process_output(payload)

                elif event_type == "status":
                    self.status_badge.config(
                        text="● ONLINE",
                        bg="#065f46",
                        fg="#34d399"
                    )

                    self.card_status.config(
                        text="RUNNING",
                        fg="#34d399"
                    )

                    self.log(
                        "C++ engine is running.",
                        "SUCCESS"
                    )

                elif event_type == "exit":
                    self.is_running = False

                    self.btn_start.config(
                        state=tk.NORMAL,
                        bg="#059669"
                    )

                    self.btn_stop.config(
                        state=tk.DISABLED,
                        bg="#475569"
                    )

                    self.status_badge.config(
                        text="● OFFLINE",
                        bg="#334155",
                        fg="#facc15"
                    )

                    self.card_status.config(
                        text="STOPPED",
                        fg="#facc15"
                    )

                    if self.stop_event.is_set():
                        self.log(
                            "Monitoring stopped.",
                            "WARNING"
                        )
                    else:
                        self.log(
                            f"Engine exited with code {payload}.",
                            "WARNING"
                        )

                elif event_type == "error":
                    self.log(
                        f"Process error: {payload}",
                        "ERROR"
                    )

                    self.is_running = False

                    self.btn_start.config(
                        state=tk.NORMAL,
                        bg="#059669"
                    )

                    self.btn_stop.config(
                        state=tk.DISABLED,
                        bg="#475569"
                    )

                    self.status_badge.config(
                        text="● ERROR",
                        bg="#7f1d1d",
                        fg="#fecaca"
                    )

                    self.card_status.config(
                        text="ERROR",
                        fg="#f87171"
                    )

        except queue.Empty:
            pass

        self.root.after(
            100,
            self.process_queue
        )

    # --------------------------------------------------
    # Stop and shutdown
    # --------------------------------------------------

    def stop_monitoring(self):
        if not self.is_running:
            return

        self.stop_event.set()

        with self.process_lock:
            process = self.process

        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

        self.log(
            "Stopping monitoring engine...",
            "WARNING"
        )

        self.btn_stop.config(
            state=tk.DISABLED
        )

    def on_close(self):
        self.stop_event.set()

        with self.process_lock:
            process = self.process

        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = LiveSOCDashboard(root)
    root.mainloop() 
