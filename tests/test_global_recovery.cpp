// Golden tests for GlobalObjectRecovery (Phase 8): constant-address data
// accesses become named g_data_* symbols in the native view.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/decompile.hpp"
#include "centrifuge/global_recovery.hpp"
#include "centrifuge/memory.hpp"
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

struct Fixture {
    MemoryImage memory;
    std::vector<uint8_t> code;
    Fixture() : code(512, 0xCC) {}
    bool read(uint64_t a, void* buf, size_t n) const {
        if (a < 0x1000 || a + n > 0x1000 + code.size()) return false;
        std::memcpy(buf, code.data() + (a - 0x1000), n);
        return true;
    }
};

// mov rax, [rip+0x1405dff9]; mov [rip+0x1405dff6], rax; ret
// rip-relative (addr 0x1000: 7-byte instr, next rip = 0x1007/0x100e):
//   load  = 0x1405f000 - 0x1007 = 0x1405dff9
//   store = 0x1405f004 - 0x100e = 0x1405dff6
std::vector<uint8_t> func_globals() {
    return {0x48, 0x8B, 0x05, 0xF9, 0xDF, 0x05, 0x14,
            0x48, 0x89, 0x05, 0xF6, 0xDF, 0x05, 0x14,
            0xC3};
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

    Fixture fixture;
    std::memcpy(fixture.code.data(), func_globals().data(),
                func_globals().size());
    fixture.memory.addBlock(".text", 0x1000, fixture.code, 0x20 /*r-x*/);
    fixture.memory.addBlock(".data", 0x1405f000,
                            std::vector<uint8_t>(0x100, 0), 0x40 /*rw-*/);
    auto read = [&](uint64_t a, void* b, size_t n) {
        return fixture.read(a, b, n);
    };

    CfgBuilder cfg;
    CHECK(cfg.build(eng, read, 0x1000, 0x1100), "globals: cfg build");

    GlobalObjectRecovery globals;
    globals.analyze(cfg, fixture.memory);
    CHECK(!globals.objects().empty(), "globals: objects recovered");
    if (!globals.objects().empty()) {
        const GlobalObject& object = globals.objects().front();
        CHECK(object.address == 0x1405f000,
              "globals: object at 0x1405f000");
        CHECK(object.name.rfind("g_data_", 0) == 0,
              "globals: named g_data_*");
    }

    const std::string native =
        decompile(eng, read, 0x1000, 0x1100,
                  [](uint64_t) { return std::string(); }, nullptr,
                  "x86-64-win64", false, nullptr, &globals);
    CHECK(native.find("g_data_") != std::string::npos,
          "globals: native output names the global");
    CHECK(native.find("0x1405f000") == std::string::npos,
          "globals: raw absolute address replaced");

    if (failures == 0) {
        std::printf("test_global_recovery: all checks passed\n");
        return 0;
    }
    std::printf("test_global_recovery: %d FAILURES\n", failures);
    return 1;
}
