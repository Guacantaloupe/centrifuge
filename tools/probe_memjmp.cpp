// Probe: dump p-code for `mov rax,[rcx]; jmp [rax+0x18]` (memory-indirect
// tail jump) to see the BRANCHIND operand shape.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/sleigh.hpp"

using namespace centrifuge;

int main(int argc, char** argv) {
    std::ifstream f(argv[1], std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) return 1;

    // test rcx,rcx; je +7; mov rax,[rcx]; jmp [rax+0x18]; ret
    const std::vector<uint8_t> bytes = {
        0x48, 0x85, 0xC9, 0x74, 0x07, 0x48, 0x8B, 0x01,
        0x48, 0xFF, 0x60, 0x18, 0xC3};
    std::vector<uint8_t> image(4096, 0x90);
    std::memcpy(image.data(), bytes.data(), bytes.size());
    auto read = [&](uint64_t a, void* buf, size_t n) -> bool {
        if (a < 0x1000 || a + n > 0x1000 + image.size()) return false;
        std::memcpy(buf, image.data() + (a - 0x1000), n);
        return true;
    };
    uint64_t addr = 0x1000;
    for (int i = 0; i < 5; ++i) {
        PcodeInsn pi;
        std::string disErr;
        if (!eng.disassemble(read, addr, pi, disErr)) break;
        std::printf("--- @0x%llx kind=%d text='%s' targetKnown=%d\n",
                    static_cast<unsigned long long>(pi.addr),
                    static_cast<int>(pi.kind), pi.text.c_str(),
                    pi.targetKnown ? 1 : 0);
        for (const auto& op : pi.ops) {
            std::printf("  op=%d out=%llu in0=%llu in1=%llu\n",
                        static_cast<int>(op.op),
                        static_cast<unsigned long long>(op.out),
                        static_cast<unsigned long long>(op.in0),
                        static_cast<unsigned long long>(op.in1));
            for (const uint64_t id : {op.out, op.in0, op.in1, op.in2}) {
                const Varnode* v = pi.find(id);
                if (v)
                    std::printf("      id=%llu kind=%d offset=%llu size=%d\n",
                                static_cast<unsigned long long>(id),
                                static_cast<int>(v->kind),
                                static_cast<unsigned long long>(v->offset),
                                v->size);
            }
        }
        addr = pi.nextAddr;
    }
    return 0;
}
