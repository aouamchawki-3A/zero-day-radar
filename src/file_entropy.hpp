#pragma once
#include <cmath>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <vector>
namespace radar {
// Shannon entropy (bits/byte) of the first 64 KiB. Content is never logged.
inline bool fileEntropy(const std::filesystem::path& p, double& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::vector<unsigned char> buf(64 * 1024);
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const std::size_t n = static_cast<std::size_t>(in.gcount());
    if (n < 1024) return false;  // too small to judge
    std::size_t cnt[256] = {0};
    for (std::size_t i = 0; i < n; ++i) ++cnt[buf[i]];
    double h = 0.0;
    for (std::size_t c : cnt) {
        if (!c) continue;
        double pr = static_cast<double>(c) / static_cast<double>(n);
        h -= pr * std::log2(pr);
    }
    out = h;
    return true;
}

} // namespace radar
