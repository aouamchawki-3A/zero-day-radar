#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Day Radar v2.0 - Python Analysis Engine
مسؤول عن قراءة القواعد، حساب الإنتروبيا، وتقييم المخاطر بذكاء
"""

import os
import math

class ThreatAnalyzer:
    def __init__(self, rules_path="rules.txt"):
        self.rules = []
        self.load_rules(rules_path)

    def load_rules(self, path):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) == 3:
                            self.rules.append({
                                "level": parts[0],
                                "pattern": parts[1],
                                "desc": parts[2]
                            })
        print(f"[*] Python Engine: Successfully loaded {len(self.rules)} rules.")

    def calculate_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = text.count(chr(x)) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def evaluate_threat(self, file_path, event_type):
        score = 0
        indicators = []

        # مطابقة الأحداث مع القواعد الديناميكية
        for rule in self.rules:
            if rule["pattern"] in event_type.lower():
                score += 2
                indicators.append(rule["desc"])

        # فحص الإنتروبيا للملف إذا كان موجوداً
        if os.path.exists(file_path):
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                ent = self.calculate_entropy(content)
                if ent > 4.5:
                    score += 3
                    indicators.append(f"High Entropy detected ({ent:.2f})")

        # تقييم مستوى الخطر النهائي
        if score >= 4:
            return "HIGH THREAT", indicators
        elif score >= 2:
            return "MEDIUM THREAT", indicators
        else:
            return "LOW / SAFE", indicators

if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    # اختبار محلي للمنطق
    level, details = analyzer.evaluate_threat("/tmp/decoy_passwords.txt", "decoy_read")
    print(f"[Result] Threat Level: {level} | Details: {details}")
