import tkinter as tk
from tkinter import ttk, messagebox
import json
import subprocess
import os
import threading
import time
from soc_modules import ZeroDaySOCModules

class ZeroDayRadarGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Day Radar - Full Spectrum Threat Intelligence & SOC")
        self.root.geometry("950x720")
       
        self.monitoring_active = False
       
        # عنوان اللوحة
        title_label = tk.Label(root, text="🛡️ Zero-Day Radar - Autonomous SOC Dashboard", font=("Arial", 16, "bold"), fg="#1e293b")
        title_label.pack(pady=10)
       
        # --- القسم الأول: الاستشعار البعيد (Far-Range: CISA KEV) ---
        frame_far = tk.LabelFrame(root, text="📡 Far-Range Radar (Global CISA KEV Vulnerabilities)", font=("Arial", 11, "bold"))
        frame_far.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
       
        columns = ("cve", "vendor", "product", "level", "score")
        self.tree = ttk.Treeview(frame_far, columns=columns, show="headings", height=6)
       
        self.tree.heading("cve", text="CVE ID")
        self.tree.heading("vendor", text="Vendor")
        self.tree.heading("product", text="Product")
        self.tree.heading("level", text="Threat Level")
        self.tree.heading("score", text="Score")
       
        self.tree.column("cve", width=120, anchor=tk.CENTER)
        self.tree.column("vendor", width=140, anchor=tk.W)
        self.tree.column("product", width=180, anchor=tk.W)
        self.tree.column("level", width=120, anchor=tk.CENTER)
        self.tree.column("score", width=70, anchor=tk.CENTER)
       
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
       
        # --- القسم الثاني: الاستشعار القريب والمحرك (Near-Range & C++ Engine Telemetry) ---
        frame_near = tk.LabelFrame(root, text="🔍 Autonomous Near-Range Radar & C++ Core", font=("Arial", 11, "bold"))
        frame_near.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
       
        self.near_text = tk.Text(frame_near, height=7, bg="#0f172a", fg="#38ef7d", font=("Consolas", 10))
        self.near_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.near_text.insert(tk.END, "[*] System ready. Start Auto-Monitor or run manual scan.\n")
       
        # --- أزرار التحكم والتشغيل ---
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
       
        scan_btn = tk.Button(
            btn_frame,
            text="🚀 Run Manual Scan",
            command=self.run_full_scan,
            bg="#0284c7",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=6
        )
        scan_btn.pack(side=tk.LEFT, padx=5)
       
        self.toggle_btn = tk.Button(
            btn_frame,
            text="🟢 Start Auto-Background Monitor",
            command=self.toggle_background_monitor,
            bg="#16a34a",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=6
        )
        self.toggle_btn.pack(side=tk.LEFT, padx=5)
       
        self.load_data_from_cache()
       
    def load_data_from_cache(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
           
        if not os.path.exists("vuln_cache.json"):
            return
           
        try:
            with open("vuln_cache.json", "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    self.tree.insert("", tk.END, values=(
                        item.get("cveID"),
                        item.get("vendorProject"),
                        item.get("product"),
                        item.get("threatLevel"),
                        item.get("threatScore")
                    ))
        except Exception as e:
            print(f"Error loading cache: {e}")
           
    def run_full_scan(self):
        try:
            subprocess.run(["python3", "radar.py"], check=True)
            self.load_data_from_cache()
           
            cpp_output = ""
            if os.path.exists("./radar_engine"):
                res = subprocess.run(["./radar_engine"], capture_output=True, text=True)
                cpp_output = res.stdout
            else:
                cpp_output = "[NOTICE] C++ radar_engine binary not found.\n"
           
            honeypot_status = ZeroDaySOCModules.setup_honeypot()
            ports = ZeroDaySOCModules.scan_ports()
            auth_logs = ZeroDaySOCModules.analyze_auth_logs()
           
            is_threat = "ALERT" in honeypot_status or "WARNING" in auth_logs
            if is_threat:
                self.near_text.config(bg="#7f1d1d", fg="#fca5a5")
                messagebox.showwarning("SECURITY ALERT!", "⚠️ Suspicious activity detected locally!")
            else:
                self.near_text.config(bg="#0f172a", fg="#38ef7d")
           
            self.near_text.delete("1.0", tk.END)
            self.near_text.insert(tk.END, f"=== C++ ENGINE TELEMETRY ===\n{cpp_output}\n")
            self.near_text.insert(tk.END, f"=== NEAR-RANGE SOC SENSORS ===\n")
            self.near_text.insert(tk.END, f"• Honeypot Status : {honeypot_status}\n")
            self.near_text.insert(tk.END, f"• Local Open Ports: {', '.join(ports)}\n")
            self.near_text.insert(tk.END, f"• Auth Log Status : {auth_logs}\n")
           
        except Exception as e:
            messagebox.showerror("Error", f"Scan failed: {e}")

    def toggle_background_monitor(self):
        if not self.monitoring_active:
            self.monitoring_active = True
            self.toggle_btn.config(text="🔴 Stop Auto-Monitor", bg="#dc2626")
            # تشغيل خيط خلفي للمراقبة المستمرة
            threading.Thread(target=self._background_loop, daemon=True).start()
            messagebox.info = messagebox.showinfo("Auto-Monitor", "Background radar monitoring activated!")
        else:
            self.monitoring_active = False
            self.toggle_btn.config(text="🟢 Start Auto-Background Monitor", bg="#16a34a")
            messagebox.showinfo("Auto-Monitor", "Background radar monitoring stopped.")

    def _background_loop(self):
        while self.monitoring_active:
            # فحص محلي صامت في الخلفية كل 20 ثانية
            honeypot_status = ZeroDaySOCModules.setup_honeypot()
            ports = ZeroDaySOCModules.scan_ports()
            auth_logs = ZeroDaySOCModules.analyze_auth_logs()
           
            is_threat = "ALERT" in honeypot_status or "WARNING" in auth_logs
           
            # تحديث الواجهة بأمان من داخل الخيط الخلفي عبر root.after
            self.root.after(0, lambda: self.update_ui_background(honeypot_status, ports, auth_logs, is_threat))
           
            # الانتظار 20 ثانية قبل الفحص القادم
            time.sleep(20)

    def update_ui_background(self, honeypot, ports, logs, is_threat):
        if not self.monitoring_active:
            return
        if is_threat:
            self.near_text.config(bg="#7f1d1d", fg="#fca5a5")
        else:
            self.near_text.config(bg="#0f172a", fg="#38ef7d")
           
        self.near_text.delete("1.0", tk.END)
        self.near_text.insert(tk.END, f"--- 🔄 LIVE AUTONOMOUS MONITOR (Active 24/7) ---\n")
        self.near_text.insert(tk.END, f"• Honeypot : {honeypot}\n")
        self.near_text.insert(tk.END, f"• Ports    : {', '.join(ports)}\n")
        self.near_text.insert(tk.END, f"• Logs     : {logs}\n")
        self.near_text.insert(tk.END, f"---------------------------------------------\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = ZeroDayRadarGUI(root)
    root.mainloop()
