import os
import socket
import datetime

class ZeroDaySOCModules:
   
    # 1. نظام ملفات الطعم (Honeypot / Canary File)
    @staticmethod
    def setup_honeypot(filename="secret_keys.env"):
        """إنشاء ملف طعم وهمي ومراقبة ما إذا تم فتحه أو تعديله"""
        if not os.path.exists(filename):
            with open(filename, "w", encoding="utf-8") as f:
                f.write("# CONFIG_PASSWORD=Admin123!_DO_NOT_TOUCH\n")
            print(f"[+] Honeypot canary file created: {filename}")
        else:
            # التحقق من وقت التعديل الأخير كمؤشر حركة مريبة
            mod_time = os.path.getmtime(filename)
            current_time = datetime.datetime.now().timestamp()
            # إذا تم تعديل الملف حديثاً (خلال آخر دقيقة مثلاً)
            if (current_time - mod_time) < 60:
                return f"[ALERT 🚨] Unauthorized access/modification detected on honeypot file: {filename}!"
        return "[OK] Honeypot secure. No unauthorized interaction."

    # 2. فحص المنافذ السريع (Port Scanner)
    @staticmethod
    def scan_ports(target="127.0.0.1", ports=[21, 22, 80, 443, 4444, 8080]):
        """فحص المنافذ الحرجة محلياً لمعرفة المفتوح منها"""
        results = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((target, port))
                if result == 0:
                    results.append(f"Port {port}: OPEN 🔓")
                s.close()
            except Exception:
                pass
        return results if results else ["No critical ports open."]

    # 3. تحليل سجلات النظام (Log Analyzer - Auth Logs)
    @staticmethod
    def analyze_auth_logs():
        """فحص محاولات تسجيل الدخول الفاشلة في لينكس (إذا كان متاحاً)"""
        log_path = "/var/log/auth.log"
        failed_attempts = 0
       
        if not os.path.exists(log_path):
            return "Auth log not accessible on this environment."
           
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                # نأخذ آخر 100 سطر للتحليل السريع
                for line in lines[-100:]:
                    if "Failed password" in line:
                        failed_attempts += 1
           
            if failed_attempts > 5:
                return f"[WARNING ⚠️] High failed login attempts detected: {failed_attempts} failures!"
            else:
                return f"[OK] Auth logs normal. Failed attempts: {failed_attempts}"
        except PermissionError:
            return "[NOTICE] Root permission required to read auth logs."
        except Exception as e:
            return f"Error reading logs: {e}"
