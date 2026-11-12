#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <fcntl.h>

class PythonBridge {
    std::string python_script_path;
public:
    PythonBridge(const std::string& script_path) : python_script_path(script_path) {}

    bool send_event(const std::string& json_event) {
        int pipe_to_python[2];
        int pipe_from_python[2];

        if (pipe(pipe_to_python) == -1 || pipe(pipe_from_python) == -1) {
            std::cerr << "[-] Failed to create pipes." << std::endl;
            return false;
        }

        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "[-] Fork failed." << std::endl;
            return false;
        }

        if (pid == 0) { // عملية الابن (Python)
            dup2(pipe_to_python[0], STDIN_FILENO);
            dup2(pipe_from_python[1], STDOUT_FILENO);

            close(pipe_to_python[1]);
            close(pipe_from_python[0]);

            execlp("python3", "python3", python_script_path.c_str(), nullptr);
            _exit(1);
        } else { // عملية الأب (C++ Core)
            close(pipe_to_python[0]);
            close(pipe_from_python[1]);

            write(pipe_to_python[1], json_event.c_str(), json_event.size());
            close(pipe_to_python[1]);

            std::string response = "";
            char buffer[1024];
            ssize_t bytes_read;
            while ((bytes_read = read(pipe_from_python[0], buffer, sizeof(buffer) - 1)) > 0) {
                buffer[bytes_read] = '\0';
                response += buffer;
            }
            close(pipe_from_python[0]);

            int status;
            waitpid(pid, &status, 0);

            if (!response.empty()) {
                std::cout << response << std::endl;
                return true;
            }
        }
        return false;
    }
};

int main() {
    std::cerr << "[*] Zero-Day Radar Core Initialized. Monitoring active decoys..." << std::endl;

    PythonBridge bridge("/home/chawki/zero-day-radar/python/bridge_worker.py");

    // إعداد مراقبة الـ inotify للملف الوهمي
    int fd = inotify_init();
    if (fd < 0) {
        std::cerr << "[-] inotify_init failed." << std::endl;
        return 1;
    }

    int wd = inotify_add_watch(fd, "/tmp/zero-day-radar-decoy.txt", IN_ACCESS | IN_MODIFY);
    if (wd < 0) {
        std::cerr << "[-] Failed to watch decoy file. Make sure it exists." << std::endl;
        return 1;
    }

    std::cerr << "[+] Watching /tmp/zero-day-radar-decoy.txt for unauthorized access..." << std::endl;

    char buffer[1024];
    while (true) {
        ssize_t length = read(fd, buffer, sizeof(buffer));
        if (length < 0) break;

        // عند رصد أي وصول للملف، يتم توليد الحدث وإرساله تلقائياً
        std::string alert_event =
            R"({"schema_version": 1, "event_id": "evt-live-001", "event_type": "decoy_access", "path": "/tmp/zero-day-radar-decoy.txt", "risk_score": 80})";

        std::cout << "[>] Decoy accessed! Dispatching event to Python engine..." << std::endl;
        bridge.send_event(alert_event);
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    return 0;
}
