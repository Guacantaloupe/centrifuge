// Probe: decompile 0x14045B370 with an end that covers 0x14045B350's block
// (simulates the 4500-function-boundary merge) and check the label safety
// net emits a dangling L0x14045b350 definition.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/decompile.hpp"
#include "centrifuge/sleigh.hpp"

using namespace centrifuge;

int main(int argc, char** argv) {
    std::ifstream f(argv[1], std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) return 1;
    // Blender 5.2 image.bin is a flat tiled image; .text VA 0x140001000 is
    // at file offset 1024 (delta 0xC00).
    std::ifstream image(argv[2], std::ios::binary | std::ios::ate);
    const auto size = image.tellg();
    image.seekg(0);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    image.read(reinterpret_cast<char*>(bytes.data()), size);
    auto read = [&](uint64_t a, void* buf, size_t n) -> bool {
        const uint64_t off = a - 0x140000000 - 0xC00;
        if (off + n > bytes.size()) return false;
        std::memcpy(buf, bytes.data() + off, n);
        return true;
    };
    const std::string output =
        decompile(eng, read, 0x14045B370, 0x14045B400,
                  [](uint64_t) { return std::string(); }, nullptr,
                  "x86-64-win64", false);
    std::printf("%s\n", output.c_str());
    const bool hasGoto = output.find("goto L0x14045b350;") != std::string::npos;
    const bool hasLabel = output.find("L0x14045b350:") != std::string::npos;
    std::printf("=== goto L0x14045b350: %s ; label defined: %s ===\n",
                hasGoto ? "yes" : "no", hasLabel ? "yes" : "no");
    return 0;
}
