// Probe: mimic ProgramAnalysis::scanLeaTargets on FUN_14041F270 with the
// SpecDisassembler to see why allocator targets are not promoted.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>

#include "centrifuge/disasm.hpp"
#include "centrifuge/loader.hpp"
#include "centrifuge/sleigh.hpp"

using namespace centrifuge;

int main(int argc, char** argv) {
    std::ifstream f(argv[1], std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) return 1;
    auto loaded = loadFile(argv[2], err);
    if (!loaded) return 1;
    const Program& program = *loaded;
    std::shared_ptr<const SleighEngine> engineRef(&eng,
                                                  [](const SleighEngine*) {});
    SpecDisassembler disasm(engineRef);
    uint64_t cur = 0x14041F270;
    unsigned n = 0;
    while (n++ < 16) {
        Insn insn;
        if (!disasm.disasmOne(program.memory, cur, insn)) {
            std::printf("disasm fail @0x%llx\n",
                        static_cast<unsigned long long>(cur));
            break;
        }
        std::printf("@0x%llx size=%zu kind=%d bytes=",
                    static_cast<unsigned long long>(cur), insn.bytes.size(),
                    static_cast<int>(insn.kind));
        for (uint8_t b : insn.bytes) std::printf("%02x ", b);
        std::printf(" text='%s'\n", insn.text.c_str());
        const std::vector<uint8_t>& raw = insn.bytes;
        for (size_t i = 0; i + 7 <= raw.size(); ++i) {
            if (raw[i] != 0x48 || raw[i + 1] != 0x8D) continue;
            const uint8_t modrm = raw[i + 2];
            if ((modrm & 0xC7) != 0x05) continue;
            int32_t disp = 0;
            std::memcpy(&disp, &raw[i + 3], 4);
            const uint64_t target =
                cur + i + 7 + static_cast<uint64_t>(disp);
            std::printf("  -> lea target 0x%llx (disp=%d)\n",
                        static_cast<unsigned long long>(target), disp);
        }
        if (insn.kind == Insn::RET) break;
        if (insn.kind == Insn::JMP && insn.targetKnown) cur = insn.target;
        else cur += insn.size;
    }
    return 0;
}
