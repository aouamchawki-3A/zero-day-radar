#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <chrono>
#include <filesystem>
#include <cmath>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <GLFW/glfw3.h>
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

namespace fs = std::filesystem;

// ==========================================
// 1. المتغيرات الهندسية والمخازن الآمنة
// ==========================================
std::deque<float> threatHistory;
const size_t maxHistorySize = 100;
std::mutex dataMutex;

float currentThreatLevel = 0.0f;
bool isEngineRunning = true;
std::string decoyFilePath = "/tmp/decoy_passwords.txt";

// ==========================================
// 2. دوال مساعدة لحماية وتحديث البيانات
// ==========================================
void updateThreatData(float newLevel, const std::string& logMessage) {
    std::lock_guard<std::mutex> lock(dataMutex);
    currentThreatLevel = newLevel;
   
    threatHistory.push_back(currentThreatLevel);
    if (threatHistory.size() > maxHistorySize) {
        threatHistory.pop_front();
    }

    // كتابة التنبيه في ملف السجلات radar.log
    std::ofstream logFile("radar.log", std::ios::app);
    if (logFile.is_open()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        char timeStr[26];
        ctime_r(&now, timeStr);
        timeStr[24] = '\0'; // إزالة سطر جديد
        logFile << "[" << timeStr << "] " << logMessage << "\n";
        logFile.close();
    }
}

// دالة فحص منافذ محلية سريعة (Port Scan Detection)
bool isPortOpen(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    // ضبط مهلة الاتصال لـ 100 ملي ثانية
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    int result = connect(sock, (struct sockaddr*)&address, sizeof(address));
    close(sock);
    return (result == 0);
}

// ==========================================
// 3. المحرك الخلفي الموحد (Decoy + Port Detector)
// ==========================================
void BackgroundEngineThread() {
    // إنشاء ملف الطعم المخصص إذا لم يكن موجوداً
    if (!fs::exists(decoyFilePath)) {
        std::ofstream decoy(decoyFilePath);
        decoy << "admin:supersecret123\nroot:toor1234\n";
        decoy.close();
    }

    auto lastWriteTime = fs::last_write_time(decoyFilePath);

    while (isEngineRunning) {
        bool threatDetected = false;
        std::string alertMsg = "";
        float alertLevel = 0.0f;

        // --- أ: مراقبة ملف الطعم (Decoy File Monitoring) ---
        try {
            auto currentWriteTime = fs::last_write_time(decoyFilePath);
            if (currentWriteTime != lastWriteTime) {
                lastWriteTime = currentWriteTime;
                threatDetected = true;
                alertLevel = 9.5f; // تهديد عالي جداً
                alertMsg = "ALERT: Decoy File Modified! Tampering Detected at " + decoyFilePath;
            }
        } catch (...) {}

        // --- ب: اكتشاف البورتات المفتوحة قبل الاستغلال (Port Scanner) ---
        if (!threatDetected) {
            // فحص بورتات شائعة (SSH=22, HTTP=80, SMB=445)
            std::vector<int> targetPorts = {22, 80, 445};
            for (int p : targetPorts) {
                if (isPortOpen(p)) {
                    threatDetected = true;
                    alertLevel = 6.8f;
                    alertMsg = "ALERT: Open Port Detected on localhost:" + std::to_string(p) + " - Risk of Exploitation!";
                    break;
                }
            }
        }

        // --- ج: تحديث الحالة وإرسال التغطية للواجهة ---
        if (threatDetected) {
            updateThreatData(alertLevel, alertMsg);
        } else {
            // حالة عادية: تذبذب طبيعي منخفض في الاتصالات
            float normalTelemetry = 0.5f + static_cast<float>(rand() % 100) / 200.0f;
            updateThreatData(normalTelemetry, "INFO: Routine system state normal.");
        }

        std::this_thread::sleep_for(std::chrono::seconds(2)); // فحص كل ثانيتين
    }
}

// ==========================================
// 4. قراءة السجلات الحية للعرض
// ==========================================
std::vector<std::string> readLogs() {
    std::vector<std::string> logs;
    std::ifstream file("radar.log");
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            logs.push_back(line);
        }
    }
    if (logs.size() > 100) {
        logs.erase(logs.begin(), logs.begin() + (logs.size() - 100));
    }
    return logs;
}

// ==========================================
// 5. الدالة الرئيسية (main) وحلقة العرض الرسومي
// ==========================================
int main() {
    if (!glfwInit()) return -1;

    GLFWwindow* window = glfwCreateWindow(850, 650, "Zero-Day Radar EDR Control Center", NULL, NULL);
    if (!window) {
        glfwTerminate();
        return -1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    // تشغيل المحرك الخلفي في خيط منفصل
    std::thread engine(BackgroundEngineThread);

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // إعداد النافذة الرئيسية لتأخذ كامل الشاشة
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Zero-Day Radar - Live Monitor", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

        // --- العنونة وحالة النظام ---
        ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "=== ZERO-DAY RADAR EDR SYSTEM ===");
        ImGui::Separator();

        float pulse = (sin(ImGui::GetTime() * 6.0f) + 1.0f) * 0.5f;
        ImGui::Text("Engine Status: ");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.0f, 0.3f + (0.7f * pulse), 0.0f, 1.0f), "[ ACTIVE / PROTECTED ]");
       
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), " | Decoy Path: %s", decoyFilePath.c_str());
        ImGui::Separator();

        // --- 1. الرسم البياني النبضي والتفاعلي ---
        std::vector<float> localPlotData;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            localPlotData.assign(threatHistory.begin(), threatHistory.end());
        }

        if (!localPlotData.empty()) {
            ImGui::Text("Threat Rate / File & Port Telemetry Live Plot:");
            ImGui::PlotLines("##ThreatPlot", localPlotData.data(), (int)localPlotData.size(), 0, "Threat Level Telemetry", 0.0f, 10.0f, ImVec2(ImGui::GetContentRegionAvail().x, 90));
        } else {
            ImGui::Text("Waiting for threat telemetry data...");
        }

        ImGui::Spacing();
        ImGui::Separator();

        // --- 2. لوحة الأزرار السريعة ---
        ImGui::Text("Quick Actions:");
        if (ImGui::Button("Trigger Test Decoy Alert", ImVec2(180, 25))) {
            updateThreatData(9.0f, "TEST_ALERT: Simulated attacker touched decoy!");
        }
        ImGui::SameLine();
        if (ImGui::Button("Refresh Logs", ImVec2(120, 25))) {
            // يتم التحديث تلقائياً في الحلقة
        }
        ImGui::Separator();

        // --- 3. نافذة السجلات الملونة والمباشرة ---
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Live Security & Intrusion Logs:");
        ImGui::BeginChild("LogRegion", ImVec2(0, 250), true, ImGuiWindowFlags_HorizontalScrollbar);
       
        std::vector<std::string> currentLogs = readLogs();
        for (const auto& log : currentLogs) {
            if (log.find("ALERT") != std::string::npos) {
                ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "%s", log.c_str());
            } else if (log.find("INFO") != std::string::npos) {
                ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "%s", log.c_str());
            } else {
                ImGui::TextUnformatted(log.c_str());
            }
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();

        ImGui::End();

        // --- التقديم الرسومي ---
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.12f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // إيقاف المحرك الخلفي بنظافة عند الخروج
    isEngineRunning = false;
    if (engine.joinable()) {
        engine.join();
    }

    // تنظيف الموارد
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
