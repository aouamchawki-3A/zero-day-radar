import requests
import json
import os
from datetime import datetime, timedelta

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev():
    try:
        print("[*] Fetching CISA KEV feed...")
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
       
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
       
        cutoff_date = datetime.now() - timedelta(days=90)
        results = []

        for vuln in vulnerabilities:
            date_added_str = vuln.get("dateAdded")
            if not date_added_str:
                continue
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                if date_added < cutoff_date:
                    continue
            except ValueError:
                continue
            results.append(vuln)

        results.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        return results
    except Exception as e:
        print(f"[-] Error fetching data: {e}")
        return []

def analyze_vulnerability(vuln):
    score = 0
    if vuln.get("knownRansomwareCampaignUse", "").strip().lower() == "known":
        score += 5
       
    date_added_str = vuln.get("dateAdded")
    if date_added_str:
        try:
            days = (datetime.now() - datetime.strptime(date_added_str, "%Y-%m-%d")).days
            if days <= 14: score += 4
            elif days <= 30: score += 2
        except ValueError:
            pass
           
    level = "CRITICAL 🔴" if score >= 7 else "HIGH 🟠" if score >= 4 else "MEDIUM 🟡" if score >= 2 else "LOW 🟢"
    return score, level

def export_to_json(vulnerabilities):
    data_to_export = []
    for vuln in vulnerabilities:
        score, level = analyze_vulnerability(vuln)
        data_to_export.append({
            "cveID": vuln.get("cveID", "N/A"),
            "vendorProject": vuln.get("vendorProject", "N/A"),
            "product": vuln.get("product", "N/A"),
            "dateAdded": vuln.get("dateAdded", "N/A"),
            "threatScore": score,
            "threatLevel": level
        })
   
    with open("vuln_cache.json", "w", encoding="utf-8") as f:
        json.dump(data_to_export, f, indent=4)
    print("[+] Cache exported to vuln_cache.json successfully.")

def main():
    vulns = fetch_cisa_kev()
    if not vulns:
        return
    print(f"[+] Total filtered vulnerabilities: {len(vulns)}")
    export_to_json(vulns)

if __name__ == "__main__":
    main()
