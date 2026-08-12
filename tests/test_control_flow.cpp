// Golden tests for ControlFlowStructuring (Phase 9): multi-block while
// loops (straight-line body chains) structured instead of goto chains.
// Uses RISC-V (integer-register branch conditions -> condition-only header).
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/decompile.hpp"
#include "centrifuge/sleigh.hpp"

using namespace centrifuge;

namespace {

int failures = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("FAIL: %s\n", what);                                 \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

struct Image {
    std::vector<uint8_t> bytes;
    Image() : bytes(1024, 0) {}
    bool read(uint64_t a, void* buf, size_t n) const {
        if (a < 0x1000 || a + n > 0x1000 + bytes.size()) return false;
        std::memcpy(buf, bytes.data() + (a - 0x1000), n);
        return true;
    }
};

void put(Image& img, uint64_t addr, const std::vector<uint8_t>& data) {
    std::memcpy(img.bytes.data() + (addr - 0x1000), data.data(), data.size());
}

// i = 10; while (i != 0) { i--; } return 0;
//   addi a0, zero, 10       @0x1000
// L_check: beq a0, zero, L_exit  @0x1004 (skip 12 -> 0x1010)
//   addi a0, a0, -1         @0x1008
//   jal x0, L_check         @0x100c (-8 -> 0x1004)
// L_exit: ret               @0x1010
std::vector<uint8_t> func_loop() {
    return {0x13, 0x05, 0xA0, 0x00,  // addi a0, zero, 10
            0x63, 0x06, 0x05, 0x00,  // beq a0, zero, +12
            0x13, 0x05, 0xF5, 0xFF,  // addi a0, a0, -1
            0x6F, 0xF0, 0x9F, 0xFF,  // jal x0, -8
            0x67, 0x80, 0x00, 0x00}; // ret
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <riscv64.slaspec>\n", argv[0]);
        return 1;
    }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 1;
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) {
        std::fprintf(stderr, "spec load failed: %s\n", err.c_str());
        return 2;
    }

    Image img;
    put(img, 0x1000, func_loop());
    auto read = [&](uint64_t a, void* b, size_t n) { return img.read(a, b, n); };
    const std::string output =
        decompile(eng, read, 0x1000, 0x1100,
                  [](uint64_t) { return std::string(); }, nullptr, "riscv64");
    std::printf("%s\n", output.c_str());
    // The 2-body-block loop (beq header + addi body + jal backedge) must
    // structure as a while loop instead of three gotos.
    CHECK(output.find("while (") != std::string::npos,
          "loop: structured as while");
    CHECK(output.find("goto L0x1004") == std::string::npos,
          "loop: backedge goto suppressed");

    if (failures == 0) {
        std::printf("test_control_flow: all checks passed\n");
        return 0;
    }
    std::printf("test_control_flow: %d FAILURES\n", failures);
    return 1;
}
