#pragma once

#include "../json.hpp"

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cerrno>
#include <utility>
#include <cstddef>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>

struct RadarEvent {
    std::string ts;
    std::string source;
    std::string event;
    std::string rule;
    std::string level;
    std::string desc;
    std::string detail;
};

inline bool parseEvent(const std::string& line, RadarEvent& out) {
    try {
        const auto j = nlohmann::json::parse(line);

        if (!j.is_object()) {
            return false;
        }

        RadarEvent parsed;

        auto getString = [&](const char* key, std::string& value) {
            auto it = j.find(key);

            if (it == j.end()) {
                value.clear();
                return true;
            }

            if (!it->is_string()) {
                return false;
            }

            value = it->get<std::string>();
            return true;
        };

        if (!getString("ts", parsed.ts) ||
            !getString("source", parsed.source) ||
            !getString("event", parsed.event) ||
            !getString("rule", parsed.rule) ||
            !getString("level", parsed.level) ||
            !getString("desc", parsed.desc) ||
            !getString("detail", parsed.detail)) {
            return false;
        }

        if (parsed.ts.empty()) {
            return false;
        }

        out = std::move(parsed);
        return true;

    } catch (const nlohmann::json::exception&) {
        return false;
    }
}

class EngineClient {
public:
    using Callback = std::function<void(const RadarEvent&)>;

    EngineClient() = default;

    EngineClient(const EngineClient&) = delete;
    EngineClient& operator=(const EngineClient&) = delete;

    bool start(
    const std::string& binary,
    const std::string& decoy,
    Callback cb
) {
   if (activeReader_ == this) {
    return false;
}
std::lock_guard<std::mutex> lock(lifecycleMutex_);

if (running_.load()) {
    return false;
}

if (binary.empty() || decoy.empty()) {
    return false;
}

if (reader_.joinable() || pid_ > 0 || readFd_ >= 0) {
    stopLocked();
}
    int outputPipe[2] = {-1, -1};
    int execPipe[2] = {-1, -1};

    if (pipe(outputPipe) < 0) {
        return false;
    }

    if (pipe(execPipe) < 0) {
        close(outputPipe[0]);
        close(outputPipe[1]);
        return false;
    }

    int descriptors[] = {
        outputPipe[0], outputPipe[1],
        execPipe[0], execPipe[1]
    };

    for (int fd : descriptors) {
        int flags = fcntl(fd, F_GETFD);

        if (flags < 0 ||
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
            close(outputPipe[0]);
            close(outputPipe[1]);
            close(execPipe[0]);
            close(execPipe[1]);
            return false;
        }
    }

    pid_t child = fork();

    if (child < 0) {
        close(outputPipe[0]);
        close(outputPipe[1]);
        close(execPipe[0]);
        close(execPipe[1]);
        return false;
    }

    if (child == 0) {
        close(outputPipe[0]);
        close(execPipe[0]);

        if (dup2(outputPipe[1], STDOUT_FILENO) < 0) {
            int childError = errno;
ssize_t written = write(execPipe[1], &childError, sizeof(childError));
(void)written;
        _exit(127);
        }

        close(outputPipe[1]);

        char* const args[] = {
            const_cast<char*>(binary.c_str()),
            const_cast<char*>(decoy.c_str()),
            nullptr
        };
       execv(binary.c_str(), args);

int childError = errno;
ssize_t written = write(
    execPipe[1],
    &childError,
    sizeof(childError)
);
(void)written;
_exit(127);
    }

    close(outputPipe[1]);
    outputPipe[1] = -1;

    close(execPipe[1]);
    execPipe[1] = -1;

    int childError = 0;
    std::size_t received = 0;
    bool execPipeReadFailed = false;

    while (received < sizeof(childError)) {
        ssize_t n = read(
            execPipe[0],
            reinterpret_cast<char*>(&childError) + received,
            sizeof(childError) - received
        );

        if (n > 0) {
            received += static_cast<std::size_t>(n);
            continue;
        }

        if (n == 0) {
            break;
        }

        if (errno == EINTR) {
            continue;
        }

        execPipeReadFailed = true;
        break;
    }

    close(execPipe[0]);
    execPipe[0] = -1;

    if (execPipeReadFailed || received != 0) {
        kill(child, SIGTERM);

        while (waitpid(child, nullptr, 0) < 0 &&
               errno == EINTR) {
        }

        close(outputPipe[0]);
        return false;
    }

    int flags = fcntl(outputPipe[0], F_GETFL);

    if (flags < 0 ||
        fcntl(outputPipe[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        kill(child, SIGTERM);

        while (waitpid(child, nullptr, 0) < 0 &&
               errno == EINTR) {
        }

        close(outputPipe[0]);
        return false;
    }

    readFd_ = outputPipe[0];
    outputPipe[0] = -1;

    pid_ = child;
    readerStop_ = false;
    running_ = true;

    try {
        reader_ = std::thread(
[this, cb = std::move(cb)]() {
    activeReader_ = this;
    readEvents(cb);
    activeReader_ = nullptr;
}
        );
    } catch (...) {
        running_ = false;
        readerStop_ = true;

        kill(pid_, SIGTERM);

        while (waitpid(pid_, nullptr, 0) < 0 &&
               errno == EINTR) {
        }

        pid_ = -1;

        close(readFd_);
        readFd_ = -1;

        return false;
    }

    return true;
}


void stop() {
    if (activeReader_ == this) {
        readerStop_ = true;
        stopProcess();
        return;
    }

    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    stopLocked();
}
private:
 void stopProcess() {
        std::lock_guard<std::mutex> lock(processMutex_);
        if (pid_ > 0) {
            kill(pid_, SIGTERM);

            int status = 0;
            bool exited = false;

            const auto deadline =
                std::chrono::steady_clock::now() +
                std::chrono::seconds(3);

            while (std::chrono::steady_clock::now() < deadline) {
                pid_t result = waitpid(pid_, &status, WNOHANG);

                if (result == pid_) {
                    exited = true;
                    break;
                }

                if (result < 0 && errno == ECHILD) {
                    exited = true;
                    break;
                }

                if (result < 0 && errno != EINTR) {
                    break;
                }

                std::this_thread::sleep_for(
                    std::chrono::milliseconds(50)
                );
            }

            if (!exited) {
                kill(pid_, SIGKILL);

                while (true) {
                    pid_t result = waitpid(pid_, &status, 0);

                    if (result == pid_ ||
                        (result < 0 && errno == ECHILD)) {
                        break;
                    }

                    if (result < 0 && errno != EINTR) {
                        break;
                    }
                }
            }

            pid_ = -1;
        }
}

void stopLocked() {
    running_ = false;
    stopProcess();
        // Ask the reader to finish. It owns no descriptor cleanup.
        readerStop_ = true;

        if (reader_.joinable()) {
            reader_.join();
        }

        if (readFd_ >= 0) {
            close(readFd_);
            readFd_ = -1;
        }
    }
public:
    bool isRunning() const {
        return running_.load();
    }

    ~EngineClient() {
        stop();
    }

private:
    void deliverLine(const std::string& line, const Callback& cb) {
        RadarEvent ev;

        if (parseEvent(line, ev) && cb) {
            try {
                cb(ev);
            } catch (...) {
                // Ignore callback exceptions.
            }
        }
    }

    void readEvents(const Callback& cb) {
        std::string pending;
        char buffer[4096];

        bool finished = false;

        while (!finished) {
            pollfd pfd{readFd_, POLLIN, 0};

            int result = poll(&pfd, 1, 100);

            if (result < 0) {
                if (errno == EINTR) {
                    continue;
                }

                break;
            }

            if (result == 0) {
                if (readerStop_.load()) {
                    break;
                }

                continue;
            }

            if (pfd.revents & POLLNVAL) {
                break;
            }

            if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
                while (true) {
                    ssize_t n = read(readFd_, buffer, sizeof(buffer));

                    if (n > 0) {
                        pending.append(
                            buffer,
                            static_cast<std::size_t>(n)
                        );

                        std::size_t pos;

                        while ((pos = pending.find('\n')) !=
                               std::string::npos) {
                            std::string line =
                                pending.substr(0, pos);

                            pending.erase(0, pos + 1);

                            deliverLine(line, cb);
                        }

                        continue;
                    }

                    if (n == 0) {
                        finished = true;
                        break;
                    }

                    if (errno == EINTR) {
                        continue;
                    }

                    if (errno == EAGAIN ||
                        errno == EWOULDBLOCK) {
                        break;
                    }

                    finished = true;
                    break;
                }
            }

            if (readerStop_.load()) {
                break;
            }
        }

        // Process a final JSON line without a trailing newline.
        if (!pending.empty()) {
            deliverLine(pending, cb);
        }

 while (!readerStop_.load()) {
            {
                std::lock_guard<std::mutex> lock(processMutex_);

                if (pid_ <= 0) {
                    break;
                }

                pid_t result = waitpid(pid_, nullptr, WNOHANG);

                if (result == pid_ ||
                    (result < 0 && errno == ECHILD)) {
                    pid_ = -1;
                    break;
                }

                if (result < 0 && errno != EINTR) {
                    break;
                }
            }

            std::this_thread::sleep_for(
                std::chrono::milliseconds(50)
            );
        }

   if (readFd_ >= 0) {
            close(readFd_);
            readFd_ = -1;
        }

        running_ = false;
    }

    std::atomic<bool> running_{false};
    std::atomic<bool> readerStop_{false};

inline static thread_local EngineClient* activeReader_ = nullptr;

std::mutex lifecycleMutex_;
std::mutex processMutex_;

    std::thread reader_;

    pid_t pid_ = -1;
    int readFd_ = -1;
};
