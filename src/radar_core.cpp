// Zero-Day Radar - Core Engine v3.2
// Detection engine. Emits one JSON object per line (JSON Lines) on stdout and,
// if LOG_FILE is set, appends the same lines to that file. Diagnostics: stderr.
//
// Detectors:
//   decoy    - honeypot file access/tamper (inotify)
//   listener - new/closed TCP listening ports (/proc/net/tcp{,6})
//   scanner  - high-entropy files recently modified under SCAN_PATH
//
// Config:  ./radar.conf (or RADAR_CONF_PATH)   Rules: ./rules.txt (or RADAR_RULES_PATH)
// Decoy path precedence: argv[1] > RADAR_MONITOR_PATH > DECOY_PATH > /tmp/decoy_passwords.txt
#include "file_entropy.hpp"
#include <sys/stat.h>
#include <sys/inotify.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::atomic<bool> g_stop{false};
void onSignal(int) { g_stop = true; }

// ---------------------------------------------------------------- helpers
std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    return s.substr(b, s.find_last_not_of(ws) - b + 1);
}

std::string expandHome(const std::string& p) {
    if (!p.empty() && p[0] == '~' && (p.size() == 1 || p[1] == '/')) {
        if (const char* h = std::getenv("HOME")) return std::string(h) + p.substr(1);
    }
    return p;
}

std::string dirOf(const std::string& path) { std::string t = path; return dirname(&t[0]); }
std::string baseOf(const std::string& path) { std::string t = path; return basename(&t[0]); }

std::string isoNow() {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    tm utc{};
    gmtime_r(&ts.tv_sec, &utc);
    char buf[64];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                  utc.tm_hour, utc.tm_min, utc.tm_sec,
                  static_cast<int>(ts.tv_nsec / 1000000));
    return buf;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
                else out += static_cast<char>(c);
        }
    }
    return out;
}

// ----------------------------------------------------------------- config
struct Config {
    std::string scanPath, quarantineDir, logFile, decoyPath;
    int scanInterval = 5;            // seconds
    double entropyThreshold = 7.5;   // bits per byte (max 8)
};
Config g_cfg;

void loadConfig(const std::string& path, bool required) {
    std::ifstream in(path);

    if (!in) {
        std::cerr << (required ? "[!] " : "[*] ")
                  << "No config file (" << path
                  << "): file scanner disabled, no log file\n";
        return;
    }

    std::string line;
    int lineNo = 0;

    while (std::getline(in, line)) {
        ++lineNo;
        line = trim(line);

        if (line.empty() || line[0] == '#')
            continue;

        auto eq = line.find('=');

        if (eq == std::string::npos) {
            std::cerr << "[!] config:" << lineNo
                      << ": expected KEY=VALUE\n";
            continue;
        }

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if (val.size() >= 2 &&
            ((val.front() == '"' && val.back() == '"') ||
             (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.size() - 2);
        }

        val = expandHome(val);

        try {
            if (key == "SCAN_PATH") {
                g_cfg.scanPath = val;
            } else if (key == "QUARANTINE_DIR") {
                g_cfg.quarantineDir = val;
            } else if (key == "LOG_FILE") {
                g_cfg.logFile = val;
            } else if (key == "DECOY_PATH") {
                g_cfg.decoyPath = val;
            } else if (key == "SCAN_INTERVAL") {
                size_t pos = 0;
                int v = std::stoi(val, &pos);

                if (pos != val.size() || v < 1 || v > 3600)
                    throw std::out_of_range("invalid SCAN_INTERVAL");

                g_cfg.scanInterval = v;
            } else if (key == "ENTROPY_THRESHOLD") {
                size_t pos = 0;
                double v = std::stod(val, &pos);

                if (pos != val.size() ||
                    !std::isfinite(v) ||
                    v <= 0.0 ||
                    v > 8.0) {
                    throw std::out_of_range("invalid ENTROPY_THRESHOLD");
                }

                g_cfg.entropyThreshold = v;
            } else {
                std::cerr << "[!] config:" << lineNo
                          << ": unknown key '" << key << "'\n";
            }
        } catch (const std::exception&) {
            std::cerr << "[!] config:" << lineNo
                      << ": invalid value for " << key
                      << " ('" << val << "'), keeping default\n";
        }
    }

    if (in.bad()) {
        std::cerr << "[!] Error while reading config file: "
                  << path << "\n";
    }
}
// ------------------------------------------------------------------ rules
struct Rule { std::string level, desc; };
std::map<std::string, Rule> g_rules;

void loadRules(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        std::cerr << "[!] Rules file not found (" << path << "): all events default to MEDIUM\n";
        return;
    }
    std::string line;
    int lineNo = 0, loaded = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto p1 = line.find('|');
        auto p2 = (p1 == std::string::npos) ? p1 : line.find('|', p1 + 1);
        if (p2 == std::string::npos) {
            std::cerr << "[!] rules:" << lineNo << ": expected 'LEVEL | KEY | DESC'\n";
            continue;
        }
        std::string level = trim(line.substr(0, p1));
        for (auto& c : level) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        std::string key = trim(line.substr(p1 + 1, p2 - p1 - 1));
        if ((level != "HIGH" && level != "MEDIUM" && level != "LOW") || key.empty()) {
            std::cerr << "[!] rules:" << lineNo << ": bad level or empty key, skipped\n";
            continue;
        }
        g_rules[key] = {level, trim(line.substr(p2 + 1))};
        ++loaded;
    }
    std::cerr << "[*] Loaded " << loaded << " rules from " << path << "\n";
}

std::string ruleKeyFor(const std::string& source, const std::string& event) {
    if (source == "decoy") {
        if (event == "access" || event == "open") return "decoy_read";
        if (event == "overflow") return "events_lost";
        return "decoy_tamper";
    }
    if (source == "listener") return event == "opened" ? "new_listener" : "listener_closed";
    if (source == "scanner") return "high_entropy";
    return "unknown";
}

// ----------------------------------------------------------------- output
std::mutex g_outMu;
std::ofstream g_log;

void openLog(const std::string& path) {
    if (path.empty()) return;
    std::error_code ec;
    auto sz = fs::file_size(path, ec);
    if (!ec && sz > 5u * 1024 * 1024) fs::rename(path, path + ".1", ec);  // simple rotation
    g_log.open(path, std::ios::app);
    if (!g_log) std::cerr << "[!] Cannot open LOG_FILE " << path << ": " << std::strerror(errno) << "\n";
}

void emit(const std::string& source, const std::string& event, const std::string& detail) {
    const std::string key = ruleKeyFor(source, event);
    auto it = g_rules.find(key);
    const std::string level = (it != g_rules.end()) ? it->second.level : "MEDIUM";
    const std::string desc  = (it != g_rules.end()) ? it->second.desc : "";

    std::ostringstream o;
    o << "{\"ts\":\"" << isoNow() << "\",\"source\":\"" << source
      << "\",\"event\":\"" << event << "\",\"rule\":\"" << key
      << "\",\"level\":\"" << level << "\",\"desc\":\"" << jsonEscape(desc)
      << "\",\"detail\":\"" << jsonEscape(detail) << "\"}";

    std::lock_guard<std::mutex> lk(g_outMu);
    std::cout << o.str() << std::endl;
    if (g_log.is_open()) g_log << o.str() << '\n' << std::flush;
}

// ------------------------------------------------------- decoy (inotify)
const char* eventName(uint32_t mask) {
    if (mask & IN_ACCESS)     return "access";
    if (mask & IN_OPEN)       return "open";
    if (mask & IN_MODIFY)     return "modify";
    if (mask & IN_ATTRIB)     return "attrib";
    if (mask & IN_DELETE)     return "delete";
    if (mask & IN_MOVED_FROM) return "moved_from";
    if (mask & IN_MOVED_TO)   return "moved_to";
    if (mask & IN_CREATE)     return "create";
    return nullptr;
}

bool ensureDecoy(const std::string& path) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) {
        if (errno == EEXIST) {
            struct stat st{};

            if (lstat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
                return true;
            }

            std::cerr << "[!] Existing decoy path is not a regular file: "
                      << path << "\n";
            return false;
        }

        std::cerr << "[!] Cannot create decoy " << path
                  << ": " << std::strerror(errno) << "\n";
        return false;
    }

    // Synthetic placeholders only; these are not real credentials.
    const char bait[] =
        "decoy-user:NOT-A-REAL-CREDENTIAL\n"
        "backup-user:NOT-A-REAL-CREDENTIAL\n";

    size_t total = 0;
    const size_t length = sizeof(bait) - 1;

    while (total < length) {
        ssize_t n = write(fd, bait + total, length - total);

        if (n < 0) {
            if (errno == EINTR) continue;

            std::cerr << "[!] Cannot write decoy: "
                      << std::strerror(errno) << "\n";
            close(fd);
            return false;
        }

        if (n == 0) {
            std::cerr << "[!] Decoy write returned zero bytes\n";
            close(fd);
            return false;
        }

        total += static_cast<size_t>(n);
    }

    if (close(fd) < 0) {
        std::cerr << "[!] Cannot close decoy file: "
                  << std::strerror(errno) << "\n";
        return false;
    }

    std::cerr << "[*] Created decoy file: " << path << "\n";
    return true;
}


// -------------------------------------------------- listeners (/proc/net)
bool listeningPorts(std::set<int>& ports) {
    std::set<int> detected;

    for (const char* file : {"/proc/net/tcp", "/proc/net/tcp6"}) {
        std::ifstream in(file);

        if (!in.is_open()) {
            std::cerr << "[!] Cannot read " << file << "\n";
            return false;
        }

        std::string line;

        if (!std::getline(in, line)) {
            std::cerr << "[!] Invalid or empty file: " << file << "\n";
            return false;
        }

        while (std::getline(in, line)) {
            std::istringstream ss(line);
            std::string sl, local, remote, state;

            if (!(ss >> sl >> local >> remote >> state))
                continue;

            if (state != "0A")
                continue;

            auto colon = local.rfind(':');
            if (colon == std::string::npos)
                continue;

            try {
                const std::string portText = local.substr(colon + 1);
                size_t pos = 0;
                int port = std::stoi(portText, &pos, 16);

                if (pos != portText.size() || port < 0 || port > 65535)
                    continue;

                detected.insert(port);
            } catch (const std::exception&) {
                continue;
            }
        }

        if (in.bad()) {
            std::cerr << "[!] Error while reading " << file << "\n";
            return false;
        }
    }

    ports = std::move(detected);
    return true;
}

void diffListeners(std::set<int>& known) {
    std::set<int> now;

    if (!listeningPorts(now)) {
        std::cerr << "[!] Listener scan skipped; keeping previous baseline\n";
        return;
    }

    for (int p : now) {
        if (!known.count(p)) {
            emit("listener", "opened", "tcp/" + std::to_string(p));
        }
    }

    for (int p : known) {
        if (!now.count(p)) {
            emit("listener", "closed", "tcp/" + std::to_string(p));
        }
    }

    known = std::move(now);
}


// ------------------------------------------- scanner (high-entropy files)
bool skipExtension(const fs::path& p) {
    static const std::set<std::string> kCompressed = {
        ".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".jpg", ".jpeg",
        ".png", ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".ogg",
        ".flac", ".pdf", ".apk", ".deb", ".rpm", ".jar", ".whl", ".woff", ".woff2",
        ".sqlite", ".iso"};
    std::string e = p.extension().string();
    for (auto& c : e) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return kCompressed.count(e) > 0;
}

bool skipDirName(const std::string& n) {
    static const std::set<std::string> kSkip = {".git", "node_modules", ".cache", "__pycache__"};
    return kSkip.count(n) > 0;
}

void scanLoop(fs::path root) {
    using Clock = fs::file_time_type::clock;

    constexpr size_t kMaxVisited = 50000;
    auto lastScan = Clock::now();

    std::map<std::string, fs::file_time_type> alerted;
    bool warnedCap = false;
    bool warnedScanError = false;

    while (!g_stop) {
        for (int i = 0; i < g_cfg.scanInterval * 10 && !g_stop; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (g_stop) break;

        const auto passStart = Clock::now();
        size_t visited = 0;
        bool complete = true;

        std::error_code ec;
        fs::recursive_directory_iterator it(
            root, fs::directory_options::skip_permission_denied, ec
        );
        const fs::recursive_directory_iterator end;

        if (ec) {
            complete = false;
        }

        while (complete && !g_stop && it != end) {
            if (++visited > kMaxVisited) {
                complete = false;

                if (!warnedCap) {
                    std::cerr << "[!] scanner: SCAN_PATH exceeds "
                              << kMaxVisited
                              << " entries; scan incomplete\n";
                    warnedCap = true;
                }
                break;
            }

            const fs::directory_entry& entry = *it;
            std::error_code entryError;

            const bool isLink = entry.is_symlink(entryError);

            if (entryError) {
                complete = false;
            } else if (!isLink) {
                const bool isDirectory = entry.is_directory(entryError);

                if (entryError) {
                    complete = false;
                } else if (isDirectory &&
                           skipDirName(entry.path().filename().string())) {
                    it.disable_recursion_pending();
                } else if (!isDirectory) {
                    const bool isRegular = entry.is_regular_file(entryError);

                    if (entryError) {
                        complete = false;
                    } else if (isRegular && !skipExtension(entry.path())) {
                        const auto mt = entry.last_write_time(entryError);

                        if (entryError) {
                            complete = false;
                        } else if (mt > lastScan) {
                            const std::string key = entry.path().string();
                            const auto prev = alerted.find(key);

                            double entropy = 0.0;

                            if ((prev == alerted.end() || prev->second != mt) &&
                                radar::fileEntropy(entry.path(), entropy) &&
                                entropy >= g_cfg.entropyThreshold) {

                                char value[16];
                                std::snprintf(value, sizeof(value), "%.2f", entropy);

                                emit(
                                    "scanner",
                                    "high_entropy",
                                    key + " (entropy " + value + ")"
                                );

                                alerted[key] = mt;

                                if (alerted.size() > 10000) {
                                    alerted.clear();
                                }
                            }
                        }
                    }
                }
            }

            it.increment(ec);

            if (ec) {
                complete = false;
            }
        }

        if (complete && !g_stop) {
            lastScan = passStart;
            warnedScanError = false;
        } else if (!g_stop && !warnedScanError) {
            std::cerr << "[!] scanner: incomplete scan; "
                      << "keeping previous scan baseline\n";
            warnedScanError = true;
        }
    }
}

// ------------------------------------------------------------------- main
int run(const std::string& target) {
    const char* rp = std::getenv("RADAR_RULES_PATH");
    loadRules((rp && *rp) ? rp : "rules.txt");
    if (!ensureDecoy(target)) return 1;

    const std::string dir = dirOf(target), name = baseOf(target);

    int fd = inotify_init1(IN_CLOEXEC);
    if (fd < 0) {
        std::cerr << "[!] inotify_init1 failed: " << std::strerror(errno) << "\n";
        return 1;
    }
    const uint32_t mask = IN_ACCESS | IN_OPEN | IN_MODIFY | IN_ATTRIB |
                          IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
    int wd = inotify_add_watch(fd, dir.c_str(), mask);
    if (wd < 0) {
        std::cerr << "[!] Cannot watch " << dir << ": " << std::strerror(errno) << "\n";
        close(fd);
        return 1;
    }
    std::cerr << "[*] Zero-Day Radar Core v3.2 watching decoy: " << target << "\n";

    std::thread scanner;
    if (!g_cfg.scanPath.empty()) {
        std::error_code ec;
        if (fs::is_directory(g_cfg.scanPath, ec)) {
            std::cerr << "[*] Entropy scanner on " << g_cfg.scanPath << " every "
                      << g_cfg.scanInterval << "s (threshold " << g_cfg.entropyThreshold << ")\n";
            scanner = std::thread(scanLoop, fs::path(g_cfg.scanPath));
        } else {
            std::cerr << "[!] SCAN_PATH is not a directory (" << g_cfg.scanPath << "): scanner disabled\n";
        }
    }
    if (!g_cfg.quarantineDir.empty())
        std::cerr << "[*] QUARANTINE_DIR is set but automatic quarantine is not implemented: alerts only\n";

    alignas(inotify_event) char buf[16 * 1024];
    pollfd pfd{fd, POLLIN, 0};
    std::set<int> knownPorts;

if (!listeningPorts(knownPorts)) {
    std::cerr << "[!] Initial listener scan failed; monitoring will retry\n";
}
    auto lastScan = std::chrono::steady_clock::now();

    while (!g_stop) {
        int pr = poll(&pfd, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            std::cerr << "[!] poll: " << std::strerror(errno) << "\n";
            break;
        }
        if (std::chrono::steady_clock::now() - lastScan >= std::chrono::seconds(2)) {
            diffListeners(knownPorts);
            lastScan = std::chrono::steady_clock::now();
        }
        if (pr == 0) continue;

        ssize_t len = read(fd, buf, sizeof buf);
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            std::cerr << "[!] read: " << std::strerror(errno) << "\n";
            break;
        }
        for (char* p = buf; p < buf + len;) {
            auto* ev = reinterpret_cast<inotify_event*>(p);
            p += sizeof(inotify_event) + ev->len;
            if (ev->mask & IN_Q_OVERFLOW) {
                std::cerr << "[!] inotify queue overflow: events were lost\n";
                emit("decoy", "overflow", target);
                continue;
            }
            if (ev->len == 0 || name != ev->name) continue;
            if (const char* en = eventName(ev->mask)) emit("decoy", en, target);
        }
    }

    std::cerr << "[*] Shutting down\n";
    g_stop = true;
    if (scanner.joinable()) scanner.join();
    inotify_rm_watch(fd, wd);
    close(fd);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    struct sigaction sa{};
    sa.sa_handler = onSignal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    const char* cp = std::getenv("RADAR_CONF_PATH");
    const bool explicitConf = cp && *cp;
    loadConfig(explicitConf ? cp : "radar.conf", explicitConf);
    openLog(g_cfg.logFile);

    std::string target = "/tmp/decoy_passwords.txt";
    if (!g_cfg.decoyPath.empty()) target = g_cfg.decoyPath;
    if (const char* env = std::getenv("RADAR_MONITOR_PATH"); env && *env) target = env;
    if (argc > 1 && argv[1][0] != '\0') target = argv[1];

    return run(target);
}
