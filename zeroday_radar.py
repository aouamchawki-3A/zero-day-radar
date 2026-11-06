import requests
from datetime import datetime, timedelta

def fetch_cisa_kev(keyword=None, days_back=90):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
   
    print("[*] Connecting to CISA KEV API...")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            print(f"[+] Total vulnerabilities in feed: {len(vulnerabilities)}")
           
            filtered_vulns = []
           
            for vuln in vulnerabilities:
                # 1. تصفية حسب الكلمة المفتاحية
                if keyword:
                    text_to_search = f"{vuln.get('vendorProject', '')} {vuln.get('product', '')} {vuln.get('shortDescription', '')}".lower()
                    if keyword.lower() not in text_to_search:
                        continue
               
                # 2. تصفية حسب الأيام الأخيرة
                if days_back:
                    date_added_str = vuln.get('dateAdded')
                    if date_added_str:
                        date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                        cutoff_date = datetime.now() - timedelta(days=days_back)
                        if date_added < cutoff_date:
                            continue
               
                filtered_vulns.append(vuln)
           
            print(f"[+] Found {len(filtered_vulns)} matching vulnerabilities.")
            print("=" * 60)
           
            for vuln in filtered_vulns[-10:]:
                print(f"CVE ID      : {vuln.get('cveID')}")
                print(f"Vendor/Prod : {vuln.get('vendorProject')} - {vuln.get('product')}")
                print(f"Date Added  : {vuln.get('dateAdded')}")
                print(f"Due Date    : {vuln.get('dueDate')}")
                print(f"Description : {vuln.get('shortDescription')[:120]}...")
                print("-" * 60)
               
        else:
            print(f"[-] HTTP Error: {response.status_code}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    fetch_cisa_kev(keyword=None, days_back=90)
