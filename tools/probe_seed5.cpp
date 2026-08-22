// Probe: run findFunctions on Blender and check whether Seed 5 promotes
// allocator-table targets (0x140B0E220 etc.) from lea rip-relative stores.
#include <cstdio>
#include <memory>

#include "centrifuge/analysis.hpp"
#include "centrifuge/disasm.hpp"
#include "centrifuge/loader.hpp"

using namespace centrifuge;

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    std::string err;
    auto loaded = loadFile(argv[1], err);
    if (!loaded) {
        std::fprintf(stderr, "load failed: %s\n", err.c_str());
        return 1;
    }
    const Program& program = *loaded;
    std::unique_ptr<Disassembler> disasm = makeDisassembler(program.arch);
    std::vector<Function> funcs = findFunctions(program, disasm.get());
    std::printf("total functions: %zu\n", funcs.size());
    bool has270 = false;
    for (const Function& f : funcs) {
        if (f.addr == 0x14041F270) {
            has270 = true;
            std::printf("FUN_14041F270 found, size=%llu\n",
                        static_cast<unsigned long long>(f.size));
        }
    }
    std::printf("FUN_14041F270 present: %s\n", has270 ? "yes" : "no");
    for (uint64_t target : {0x140B0DAA0ULL, 0x140B0E220ULL, 0x140B0E4A0ULL,
                            0x140B0DFA0ULL}) {
        bool found = false;
        for (const Function& f : funcs)
            if (f.addr == target) found = true;
        std::printf("0x%llx promoted: %s\n",
                    static_cast<unsigned long long>(target),
                    found ? "YES" : "no");
    }
    return 0;
}
