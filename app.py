from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
import subprocess
import os
import json
import pathlib
from soc_modules import ZeroDaySOCModules

app = FastAPI(title="Zero-Day Radar Enterprise SOC", version="2.0")

@app.get("/", response_class=HTMLResponse)
def web_dashboard():
    """عرض واجهة الويب التفاعلية الداكنة"""
    html_path = pathlib.Path("templates/index.html")
    return html_path.read_text(encoding="utf-8")

@app.get("/api/threats")
def get_threats():
    """جلب الثغرات العالمية المحفوظة في الكاش"""
    cache_file = "vuln_cache.json"
    if not os.path.exists(cache_file):
        return []
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/soc/status")
def get_soc_status():
    """فحص الاستشعار القريب وحالة النظام محلياً"""
    honeypot = ZeroDaySOCModules.setup_honeypot()
    ports = ZeroDaySOCModules.scan_ports()
    auth_logs = ZeroDaySOCModules.analyze_auth_logs()
   
    return {
        "honeypot": honeypot,
        "open_ports": ports,
        "auth_logs": auth_logs,
        "is_threat_detected": "ALERT" in honeypot or "WARNING" in auth_logs
    }

@app.post("/api/scan/full")
def run_full_scan():
    """تنفيذ مسح شامل (جلب الثغرات + تشغيل محرك C++)"""
    try:
        # 1. تشغيل بايثون لجلب أحدث الثغرات
        subprocess.run(["python3", "radar.py"], check=True)
       
        # 2. تشغيل محرك C++ عالي الأداء
        cpp_output = ""
        if os.path.exists("./radar_engine"):
            res = subprocess.run(["./radar_engine"], capture_output=True, text=True)
            cpp_output = res.stdout
        else:
            cpp_output = "C++ binary not compiled."
           
        return {
            "status": "success",
            "message": "Full radar scan completed via Python & C++ core.",
            "cpp_telemetry": cpp_output
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
