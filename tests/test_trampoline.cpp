// Golden tests for indirect-jump trampoline recovery (data-slot jump
// boards): `mov reg, [rip+slot]; jmp *reg` must decompile to a dispatch
// tail call instead of a void body with a dead load.
//
//  - recovered runtime:  return recovered_dispatch(rax, rcx, rdx, r8, r9,
//    0, 0, 0, 0);
//  - native view:        return ((uint64_t (*)(...))(uintptr_t)rax)(rcx,
//    rdx, r8, r9);
//  - a bare `jmp *rax` on an unknown incoming register stays untouched.
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
    Image() : bytes(1024, 0x90) {}
    bool read(uint64_t a, void* buf, size_t n) const {
        if (a < 0x1000 || a + n > 0x1000 + bytes.size()) return false;
        std::memcpy(buf, bytes.data() + (a - 0x1000), n);
        return true;
    }
};

// mov rax, [rip+0x10]   ; jmp *rax
// slot lands at 0x1007 + 0x10 = 0x1017
std::vector<uint8_t> trampoline() {
    return {0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0xFF, 0xE0};
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <x86-64.slaspec>\n", argv[0]);
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

    const std::string architecture = "x86-64-win64";

    {
        // Recovered runtime: dispatch through the loaded slot value.
        Image img;
        std::memcpy(img.bytes.data(), trampoline().data(),
                    trampoline().size());
        auto read = [&](uint64_t a, void* b, size_t n) {
            return img.read(a, b, n);
        };
        const std::string output =
            decompile(eng, read, 0x1000, 0x1100,
                      [](uint64_t) { return std::string(); }, nullptr,
                      architecture, /*useRecoveredRuntime=*/true);
        std::printf("--- recovered runtime ---\n%s\n", output.c_str());
        CHECK(output.find("return recovered_dispatch(rax, rcx, rdx, r8, "
                          "r9, 0, 0, 0, 0);") != std::string::npos,
              "trampoline: dispatch tail call emitted (recovered runtime)");
        CHECK(output.find("return;") == std::string::npos,
              "trampoline: no bare void return");
    }

    {
        // Native view: indirect call through the loaded pointer.
        Image img;
        std::memcpy(img.bytes.data(), trampoline().data(),
                    trampoline().size());
        auto read = [&](uint64_t a, void* b, size_t n) {
            return img.read(a, b, n);
        };
        const std::string output =
            decompile(eng, read, 0x1000, 0x1100,
                      [](uint64_t) { return std::string(); }, nullptr,
                      architecture, /*useRecoveredRuntime=*/false);
        std::printf("--- native view ---\n%s\n", output.c_str());
        CHECK(output.find("return ((uint64_t (*)(...))(uintptr_t)rax)"
                          "(rcx, rdx, r8, r9);") != std::string::npos,
              "trampoline: indirect call emitted (native view)");
    }

    {
        // A bare `jmp *rax` on an unknown incoming register is not a
        // recognizable trampoline: the target register has no block-local
        // definition, so no dispatch may be fabricated.
        Image img;
        img.bytes[0] = 0xFF; // jmp *rax
        img.bytes[1] = 0xE0;
        auto read = [&](uint64_t a, void* b, size_t n) {
            return img.read(a, b, n);
        };
        const std::string output =
            decompile(eng, read, 0x1000, 0x1100,
                      [](uint64_t) { return std::string(); }, nullptr,
                      architecture, /*useRecoveredRuntime=*/true);
        std::printf("--- bare jmp ---\n%s\n", output.c_str());
        CHECK(output.find("recovered_dispatch") == std::string::npos,
              "bare jmp: no fabricated dispatch");
    }

    if (failures == 0) {
        std::printf("test_trampoline: all checks passed\n");
        return 0;
    }
    std::printf("test_trampoline: %d FAILURES\n", failures);
    return 1;
}
