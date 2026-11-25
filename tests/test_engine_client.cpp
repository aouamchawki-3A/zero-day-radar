#include "../src/engine_client.hpp"

#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <cassert>

int main() {

    // Test 1: Basic JSON parsing
    std::cout << "[*] Test 1: parseEvent basic\n";
    {
        RadarEvent ev;

        const std::string json =
            R"({"ts":"2026-11-23","source":"decoy","event":"open","level":"HIGH"})";

        assert(parseEvent(json, ev));
        assert(ev.ts == "2026-11-23");
        assert(ev.source == "decoy");
        assert(ev.event == "open");
        assert(ev.level == "HIGH");

        std::cout << "    OK parseEvent\n";
    }

    // Test 2: Empty input
    std::cout << "[*] Test 2: empty line\n";
    {
        RadarEvent ev;

        assert(!parseEvent("", ev));

        std::cout << "    OK empty rejected\n";
    }

    // Test 3: Escaped JSON strings
    std::cout << "[*] Test 3: escaped JSON strings\n";
    {
        RadarEvent ev;

        const std::string json =
            R"({"ts":"123","source":"test","event":"open","desc":"quoted \"text\" and \\ path"})";

        assert(parseEvent(json, ev));
        assert(ev.desc == "quoted \"text\" and \\ path");

        std::cout << "    OK escaped strings\n";
    }

    // Test 4: Malformed JSON
    std::cout << "[*] Test 4: malformed JSON\n";
    {
        RadarEvent ev;

        assert(!parseEvent("{invalid json}", ev));
        assert(!parseEvent(R"({"ts":123})", ev));
        assert(!parseEvent(R"({"ts":"ok","level":123})", ev));

        std::cout << "    OK malformed JSON rejected\n";
    }

    // Test 5: EngineClient start and stop
    std::cout << "[*] Test 5: EngineClient\n";
    {
        const std::string decoy = "/tmp/radar-test-decoy.txt";

        {
            std::ofstream f(decoy);
            assert(f.is_open());
            f << "test\n";
        }

        std::atomic<int> count{0};
        EngineClient client;

        bool ok = client.start(
            "./build/radar_core",
            decoy,
            [&](const RadarEvent& ev) {
                std::cout << "    event: "
                          << ev.source << "/"
                          << ev.event << " ["
                          << ev.level << "]\n";

                ++count;
            }
        );

        assert(ok);

        std::this_thread::sleep_for(
            std::chrono::milliseconds(300)
        );

        {
            std::ifstream trigger(decoy);
            std::string s;
            std::getline(trigger, s);
        }

        std::this_thread::sleep_for(
            std::chrono::milliseconds(700)
        );

        client.stop();

        assert(!client.isRunning());
        assert(count > 0);

        std::cout << "    OK received "
                  << count << " event(s)\n";

        // Test 6: Restart the same client
        std::cout << "[*] Test 6: restart same EngineClient\n";

        bool restarted = client.start(
            "./build/radar_core",
            decoy,
            [&](const RadarEvent&) {
                ++count;
            }
        );

        assert(restarted);

        std::this_thread::sleep_for(
            std::chrono::milliseconds(300)
        );

        client.stop();

        assert(!client.isRunning());

        std::cout << "    OK restart and stop\n";
    }
 // Test 7: Missing executable
    std::cout << "[*] Test 7: missing executable\n";
    {
        EngineClient client;
        std::atomic<int> count{0};

        const std::string missingBinary =
            "./build/radar_core_missing_for_test";

        assert(access(missingBinary.c_str(), F_OK) == -1
               && errno == ENOENT);

        bool ok = client.start(
            missingBinary,
            "/tmp/radar-test-decoy.txt",
            [&](const RadarEvent&) {
                ++count;
            }
        );

        assert(!ok);
        assert(!client.isRunning());

        client.stop();

        assert(!client.isRunning());
        assert(count.load() == 0);

        std::cout << "    OK missing executable rejected\n";
    }
    // Test 8: Automatic process exit
    std::cout << "[*] Test 8: automatic process exit\n";
    {
        EngineClient client;

        bool ok = client.start(
            "/bin/true",
            "/tmp/radar-test-decoy.txt",
            [](const RadarEvent&) {}
        );

        assert(ok);

        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(3);

        while (client.isRunning() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(50)
            );
        }

        assert(!client.isRunning());

        bool restarted = client.start(
            "/bin/true",
            "/tmp/radar-test-decoy.txt",
            [](const RadarEvent&) {}
        );

        client.stop();

        assert(restarted);

        std::cout << "    OK automatic exit and restart\n";
    }
  // Test 9: Stop from callback
    std::cout << "[*] Test 9: stop from callback\n";
    {
        EngineClient client;
        std::atomic<bool> completed{false};

        bool ok = client.start(
            "/bin/echo",
            R"({"ts":"123","source":"test"})",
            [&](const RadarEvent&) {
                client.stop();
                completed = true;
            }
        );

        assert(ok);

        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(3);

        while (!completed.load() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(50)
            );
        }

        client.stop();

        assert(completed.load());
        assert(!client.isRunning());

        std::cout << "    OK stop from callback\n";
    }
// Test 10: Concurrent stop
    std::cout << "[*] Test 10: concurrent stop\n";
    {
        EngineClient client;

        std::atomic<bool> entered{false};
        std::atomic<bool> release{false};
        std::atomic<bool> completed{false};

        bool ok = client.start(
            "/bin/echo",
            R"({"ts":"123","source":"test"})",
            [&](const RadarEvent&) {
                entered = true;

                while (!release.load()) {
                    std::this_thread::yield();
                }

                client.stop();
                completed = true;
            }
        );

        assert(ok);

        auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(3);

        while (!entered.load() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(10)
            );
        }

        assert(entered.load());

        std::thread stopper([&]() {
            client.stop();
        });

        deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(3);

        while (client.isRunning() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(10)
            );
        }

        assert(!client.isRunning());

        release = true;

        stopper.join();

        assert(completed.load());
        assert(!client.isRunning());

        std::cout << "    OK concurrent stop\n";
    }
 // Test 11: Automatic process cleanup
    std::cout << "[*] Test 11: automatic process cleanup\n";
    {
        EngineClient client;

        bool ok = client.start(
            "/bin/true",
            "/tmp/radar-test-decoy.txt",
            [](const RadarEvent&) {}
        );

        assert(ok);

        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(3);

        while (client.isRunning() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(50)
            );
        }

        assert(!client.isRunning());

        siginfo_t info{};

        int result = waitid(
            P_ALL,
            0,
            &info,
            WEXITED | WNOHANG | WNOWAIT
        );

        assert(result == -1 && errno == ECHILD);

        client.stop();

        std::cout << "    OK automatic process cleanup\n";
    }
// Test 12: Automatic file descriptor cleanup
    std::cout << "[*] Test 12: automatic FD cleanup\n";
    {
        EngineClient client;

        int before = open("/dev/null", O_RDONLY);
        assert(before >= 0);
        close(before);

        bool ok = client.start(
            "/bin/true",
            "/tmp/radar-test-decoy.txt",
            [](const RadarEvent&) {}
        );

        assert(ok);

        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(3);

        while (client.isRunning() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(50)
            );
        }

        assert(!client.isRunning());

        int after = open("/dev/null", O_RDONLY);
        assert(after >= 0);
        close(after);

        assert(before == after);

        client.stop();

        std::cout << "    OK automatic FD cleanup\n";
    }

      std::cout << "\nAll C++ tests passed!\n";

    return 0;
}
