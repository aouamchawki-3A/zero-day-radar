#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Day Radar v2.0 - Correlation & Risk Engine
محرك ربط الأحداث وتقييم المخاطر لتصنيف التهديدات بدقة
"""

import os
import json

class RiskEngine:
    def __init__(self, log_path="radar.log"):
        self.log_path = log_path

    def log_incident(self, threat_level, details, file_path):
        incident = {
            "level": threat_level,
            "target": file_path,
            "indicators": details
        }
        # كتابة السجل في ملف اللوغات الخاص بالرادار
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(incident) + "\n")
        print(f"[*] Risk Engine: Logged security incident [{threat_level}] for {file_path}")

    def evaluate_and_correlate(self, file_path, event_type, entropy_value):
        """
        ربط عدة مؤشرات معاً (مثل مسار الطعم + الإنتروبيا + نوع العملية)
        لتقليل الإنذارات الكاذبة بدلاً من الاعتماد على عنصر واحد.
        """
        risk_score = 0
        indicators = []

        # 1. فحص مسار ملف الطعم
        if "decoy" in file_path.lower():
            risk_score += 3
            indicators.append("Canary/Decoy File Interaction")

        # 2. فحص الإنتروبيا العالية
        if entropy_value > 4.5:
            risk_score += 2
            indicators.append(f"High Entropy Level ({entropy_value:.2f})")

        # 3. فحص نوع الحدث
        if "read" in event_type.lower() or "access" in event_type.lower():
            risk_score += 2
            indicators.append("Unauthorized Read Access")

        # تقييم المخاطر النهائي بناءً على الترابط
        if risk_score >= 5:
            level = "CRITICAL THREAT"
        elif risk_score >= 3:
            level = "HIGH THREAT"
        elif risk_score >= 1:
            level = "MEDIUM THREAT"
        else:
            level = "SAFE"

