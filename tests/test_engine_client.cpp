#include "../src/engine_client.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <cassert>

int main() {
    std::cout << "[*] Test 1: parseEvent basic\n";
    {
        std::string line = "{\"ts\":\"2024-01-01T00:00:00.000Z\",\"source\":\"decoy\",\"event\":\"access\",\"rule\":\"decoy_read\",\"level\":\"HIGH\",\"desc\":\"canary\",\"detail\":\"/tmp/decoy.txt\"}";
        RadarEvent ev;
        assert(parseEvent(line, ev));
        assert(ev.source == "decoy");
        assert(ev.level  == "HIGH");
        std::cout << "    OK parseEvent\n";
    }

    std::cout << "[*] Test 2: empty line\n";
    {
        RadarEvent ev;
        assert(!parseEvent("", ev));
        std::cout << "    OK empty rejected\n";
    }

    std::cout << "[*] Test 3: EngineClient\n";
    {
        const std::string decoy = "/tmp/radar-test-decoy.txt";
        std::ofstream f(decoy);
        f << "test\n";
        f.close();

        std::atomic<int> count{0};
        EngineClient client;

        bool ok = client.start("./radar_core", decoy, [&](const RadarEvent& ev) {
            std::cout << "    event: " << ev.source << "/" << ev.event
                      << " [" << ev.level << "]\n";
            ++count;
        });

        assert(ok);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        std::ifstream trigger(decoy);
        std::string s;
        std::getline(trigger, s);
        trigger.close();
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        client.stop();

        assert(count > 0);
        std::cout << "    OK received " << count << " event(s)\n";
    }

    std::cout << "\n🎉 All C++ tests passed!\n";
    return 0;
} 
