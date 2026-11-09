#include <iostream>
#include <fstream>
#include <string>
#include "json.hpp"

using json = nlohmann::json;

int main() {
    std::ifstream file("vuln_cache.json");
    if (!file.is_open()) {
        std::cerr << "[-] Error: vuln_cache.json not found. Run radar.py first!\n";
        return 1;
    }

    json vulns;
    file >> vulns;
    file.close();

    std::cout << "[*] C++ Core Engine Loaded " << vulns.size() << " Threats from Python Cache:\n";
    std::cout << "========================================================\n";

    int count = 0;
    for (const auto& v : vulns) {
        if (count >= 5) break; // عرض أول 5 تهديدات حرجة كمثال
        std::cout << "CVE ID  : " << v.value("cveID", "N/A") << "\n";
        std::cout << "Vendor  : " << v.value("vendorProject", "N/A") << "\n";
        std::cout << "Score   : " << v.value("threatScore", 0) << " (" << v.value("threatLevel", "N/A") << ")\n";
        std::cout << "--------------------------------------------------------\n";
        count++;
    }
    return 0;
}
