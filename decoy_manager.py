#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Day Radar v2.0 - Decoy & Canary Files Manager
مسؤول عن إنشاء ملفات الطعم الوهمية ورصد أي محاولة وصول أو قراءة غير مصرح بها
"""

import os
import time

DECOY_PATH = "/tmp/decoy_passwords.txt"

def create_decoy_file():
    # إنشاء ملف طعم وهمي يجذب المهاجم أو البرمجيات الخبيثة
    decoy_content = "admin_user=root\nadmin_pass=SecretZeroDay2026!#\n"
    with open(DECOY_PATH, "w", encoding="utf-8") as f:
        f.write(decoy_content)
    print(f"[*] Decoy Canary file successfully deployed at: {DECOY_PATH}")

def check_decoy_status():
    if os.path.exists(DECOY_PATH):
        print("[*] Decoy file is active and waiting for attacker interaction...")
    else:
        print("[!] Warning: Decoy file missing! Re-creating...")
        create_decoy_file()

if __name__ == "__main__":
    print("========================================")
    print("   Decoy System Security Module v2.0    ")
    print("========================================")
    create_decoy_file()

    # محاكاة بسيطة لفحص الحالة
    check_decoy_status()
