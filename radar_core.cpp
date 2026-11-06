#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <cmath>

namespace fs = std::filesystem;

// متغيرات الإعدادات العامة
std::string config_scan_path = "/home/chawki";
int config_scan_interval = 5;
std::string config_quarantine_dir = "/var/quarantine";
std::string config_log_file = "radar.log";

// 1. دالة تسجيل الأحداث (يجب أن تكون في الأعلى لكي تراها باقي الدوال)
void writeLog(const std::string& message) {
    std::ofstream log(config_log_file, std::ios::app);
    if (log.is_open()) {
        std::time_t now = std::time(nullptr);
        log << "[" << std::ctime(&now) << "] " << message << "\n";
    }
}

// 2. قراءة ملف الإعدادات الخارجي
void loadConfig(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "[!] Warning: Could not open config file. Using default settings.\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "SCAN_PATH") config_scan_path = value;
            else if (key == "SCAN_INTERVAL") config_scan_interval = std::stoi(value);
            else if (key == "QUARANTINE_DIR") config_quarantine_dir = value;
            else if (key == "LOG_FILE") config_log_file = value;
        }
    }
    std::cout << "[+] Configuration loaded successfully from " << filename << "\n";
}

// 3. دالة الحجر الصحي الذكي
void quarantineFile(const std::string& filePath) {
    if (!fs::exists(filePath)) return;
   
    if (!fs::exists(config_quarantine_dir)) {
        fs::create_directories(config_quarantine_dir);
    }

    try {
        fs::path p(filePath);
        std::string destination = config_quarantine_dir + "/" + p.filename().string();
       
        fs::rename(filePath, destination);
        chmod(destination.c_str(), 0000); // سحب كافة الصلاحيات
       
        std::string alertMsg = "[!] ALERT: Suspicious file quarantined: " + destination;
        std::cout << alertMsg << std::endl;
        writeLog(alertMsg);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "[X] Error quarantining file: " << e.what() << std::endl;
    }
}

// 4. محرك الذكاء الاصطناعي (Entropy)
double calculateEntropy(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return 0.0;

    long long byteCount[256] = {0};
    long long totalBytes = 0;
    char buffer[1024];

    while (file.read(buffer, sizeof(buffer))) {
        for (int i = 0; i < file.gcount(); ++i) {
            byteCount[(unsigned char)buffer[i]]++;
            totalBytes++;
        }
    }

    if (totalBytes == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (byteCount[i] > 0) {
            double probability = (double)byteCount[i] / totalBytes;
            entropy -= probability * std::log2(probability);
        }
    }
    return entropy;
}

bool aiEvaluateThreat(const std::string& filePath) {
    double entropy = calculateEntropy(filePath);
   
    if (entropy > 7.2) {
        std::cout << "[AI ENGINE] High entropy detected (" << std::fixed << std::setprecision(2) << entropy
                  << ") in: " << filePath << std::endl;
        return true;
    }
    return false;
}

// 5. أدوات الطعم (Canary / Decoy Files)
void createDecoyFiles() {
    std::string decoy1 = config_scan_path + "/credentials_backup.txt";
    std::string decoy2 = config_scan_path + "/financial_records.kdbx";

    if (!fs::exists(decoy1)) {
        std::ofstream file(decoy1);
        file << "CONFIDENTIAL SYSTEM PASSWORDS - DO NOT MODIFY!\nUSER: admin\nPASS: secret_key_9988\n";
        file.close();
        chmod(decoy1.c_str(), 0444);
        writeLog("Decoy file created: " + decoy1);
    }

    if (!fs::exists(decoy2)) {
        std::ofstream file(decoy2);
        file << "ENCRYPTED VAULT DATA DUMMY CONTENT...\n";
        file.close();
        chmod(decoy2.c_str(), 0444);
        writeLog("Decoy file created: " + decoy2);
    }
}

// 6. مراقب الـ USB والأجهزة الخارجية
void monitorUSBDevices() {
    std::string usbMountBase = "/media/" + std::string(getenv("USER") ? getenv("USER") : "chawki");
   
    if (fs::exists(usbMountBase)) {
        for (const auto& entry : fs::directory_iterator(usbMountBase)) {
            if (entry.is_directory()) {
                std::string usbPath = entry.path().string();
                std::string usbLog = "[!] USB Storage detected at: " + usbPath;
                std::cout << usbLog << std::endl;
                writeLog(usbLog);
            }
        }
    }
}

// 7. محرك المراقبة الحية للملفات
void startRadarEngine() {
    std::cout << "[*] Radar Engine started monitoring path: " << config_scan_path << std::endl;
    writeLog("Radar Engine started.");

    int length, i = 0;
    char buffer[438];
    int fd = inotify_init();
    if (fd < 0) {
        std::cerr << "[X] Failed to initialize inotify!" << std::endl;
        return;
    }

    int wd = inotify_add_watch(fd, config_scan_path.c_str(), IN_CREATE | IN_MODIFY);
    if (wd == -1) {
        std::cerr << "[X] Failed to add watch for path: " << config_scan_path << std::endl;
        close(fd);
        return;
    }

    while (true) {
        length = read(fd, buffer, 438);
        if (length < 0) break;

        i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            if (event->len) {
                if (event->mask & IN_CREATE) {
                    std::string fullPath = config_scan_path + "/" + event->name;
                    std::cout << "[*] New file detected: " << fullPath << std::endl;
                   
                    if (aiEvaluateThreat(fullPath)) {
                        quarantineFile(fullPath);
                    }
                }
            }
            i += sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

// 8. الدالة الرئيسية
void initRadarCore() {
    loadConfig("radar.conf");
    createDecoyFiles();
    monitorUSBDevices();
    writeLog("Zero-Day Radar Suite started successfully.");
    startRadarEngine();
}
