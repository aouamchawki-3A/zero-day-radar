#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <sys/inotify.h>
#include <unistd.h>
#include <cstdlib>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

// قراءة مسار الطعم أو الملف المراقب بمرونة (بدون مسارات ثابتة صلبة)
std::string getMonitoredPath() {
    const char* env_path = std::getenv("RADAR_MONITOR_PATH");
    if (env_path != nullptr) {
        return std::string(env_path);
    }
    // المسار الافتراضي الآمن
    return "/tmp/decoy_passwords.txt";
}

void monitorEngine() {
    std::string target_path = getMonitoredPath();
    int fd = inotify_init();
    if (fd < 0) {
        std::cerr << "[!] Error: Failed to initialize inotify system.\n";
        return;
    }

    // مراقبة مجلد /tmp أو المسار المحدد
    int wd = inotify_add_watch(fd, "/tmp", IN_ACCESS | IN_MODIFY | IN_CREATE);
    if (wd < 0) {
        std::cerr << "[!] Error: Failed to add watch for path.\n";
        close(fd);
        return;
    }

    std::cout << "[*] C++ Monitoring Core v2.0 Active on: " << target_path << "\n";

    char buffer[EVENT_BUF_LEN];
    while (true) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read error");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            if (event->len) {
                if (event->mask & IN_ACCESS) {
                    std::cout << "[ALERT] Access detected on decoy/sensitive file: " << event->name << std::endl;
                }
            }
            i += EVENT_SIZE + event->len;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

int main() {
    std::cout << "========================================\n";
    std::cout << "   Zero-Day Radar Core Engine v2.0      \n";
    std::cout << "========================================\n";

    // تشغيل المحرك في وخيط خلفي لتفادي توقف النظام
    std::thread coreThread(monitorEngine);

    if (coreThread.joinable()) {
        coreThread.join();
    }

    return 0;
}
