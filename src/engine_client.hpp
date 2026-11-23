#pragma once
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <cstdio>

struct RadarEvent {
    std::string ts, source, event, rule, level, desc, detail;
};

inline bool parseEvent(const std::string& line, RadarEvent& out) {
    auto get = [&](const std::string& key) -> std::string {
        auto pos = line.find("\"" + key + "\":\"");
        if (pos == std::string::npos) return "";
        pos += key.size() + 4;
        auto end = line.find('"', pos);
        if (end == std::string::npos) return "";
        return line.substr(pos, end - pos);
    };
    out.ts     = get("ts");
    out.source = get("source");
    out.event  = get("event");
    out.rule   = get("rule");
    out.level  = get("level");
    out.desc   = get("desc");
    out.detail = get("detail");
    return !out.ts.empty();
}

class EngineClient {
public:
    using Callback = std::function<void(const RadarEvent&)>;

    bool start(const std::string& binary, const std::string& decoy, Callback cb) {
        std::string cmd = binary + " " + decoy + " 2>/dev/null";
        pipe_ = popen(cmd.c_str(), "r");
        if (!pipe_) return false;
        running_ = true;
        thread_ = std::thread([this, cb]() {
            char buf[4096];
            while (running_ && fgets(buf, sizeof buf, pipe_)) {
                std::string line(buf);
                if (!line.empty() && line.back() == '\n') line.pop_back();
                RadarEvent ev;
                if (parseEvent(line, ev)) cb(ev);
            }
        });
        return true;
    }

    void stop() {
        running_ = false;
        if (pipe_) { pclose(pipe_); pipe_ = nullptr; }
        if (thread_.joinable()) thread_.join();
    }

    ~EngineClient() { stop(); }

private:
    FILE* pipe_ = nullptr;
    std::thread thread_;
    std::atomic<bool> running_{false};
}; 
