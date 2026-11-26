#include "../src/file_entropy.hpp"
#include <iostream>
#include <cstdlib>
#include <string>

int main() {
    char temp[] = "/tmp/radar-entropy-XXXXXX";
    if (!mkdtemp(temp)) return 1;

    auto path = std::filesystem::path(temp) / "sample.bin";
    double entropy = 0.0;
    int failed = 0;

    auto check = [&](bool ok, const char* name) {
        std::cout << (ok ? "[PASS] " : "[FAIL] ")
                  << name << '\n';
        if (!ok) ++failed;
    };

    auto test = [&](std::string data, double expected,
                    const char* name) {
        std::ofstream out(path, std::ios::binary);
        out.write(data.data(), data.size());
        out.close();

        if (!out) {
            check(false, name);
            return;
        }

        bool ok = radar::fileEntropy(path, entropy);

        check(expected < 0 ? !ok :
              ok && std::abs(entropy - expected) < 1e-9,
              name);
    };

    check(!radar::fileEntropy(path, entropy),
          "Missing file");

    test("", -1, "Empty file");
    test(std::string(1023, 'A'), -1, "Small file");
    test(std::string(1024, 'A'), 0, "Repeated bytes");
    test(std::string(512, 'A') + std::string(512, 'B'),
         1, "Two byte values");

    std::string uniform;
    for (int i = 0; i < 65536; ++i)
        uniform += static_cast<char>(i % 256);

    test(uniform, 8, "Maximum entropy");
    test(uniform + std::string(65536, 'A'),
         8, "64 KiB sample limit");

    std::filesystem::remove_all(temp);

    return failed ? 1 : 0;
}
