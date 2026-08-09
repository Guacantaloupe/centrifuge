// ghra - a Ghidra reimplementation in C++17
// tests/test_sleigh.cpp - SLEIGH-lite engine + p-code interpreter tests
//
// Usage: test_sleigh <spec.slaspec>
// Asserts disassembly of known encodings and evaluates p-code semantics.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ghra/pcode.hpp"
#include "ghra/sleigh.hpp"

using namespace ghra;

static int failures = 0;

#define CHECK(cond, msg)                                        \
    do {                                                        \
        if (!(cond)) {                                          \
            std::printf("FAIL: %s\n", msg);                     \
            failures++;                                         \
        }                                                       \
    } while (0)

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_sleigh <spec.slaspec>\n");
        return 2;
    }
    std::ifstream f(argv[1]);
    if (!f) {
        std::fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) {
        std::fprintf(stderr, "spec load failed: %s\n", err.c_str());
        return 2;
    }

    // byte source: fixed 64-byte image, little-endian
    std::vector<uint8_t> img(64, 0xCC);
    auto put = [&](uint64_t addr, uint32_t v) {
        img[addr] = static_cast<uint8_t>(v);
        img[addr + 1] = static_cast<uint8_t>(v >> 8);
        img[addr + 2] = static_cast<uint8_t>(v >> 16);
        img[addr + 3] = static_cast<uint8_t>(v >> 24);
    };
    auto read = [&](uint64_t a, void* buf, size_t n) {
        if (a + n > img.size()) return false;
        std::memcpy(buf, img.data() + a, n);
        return true;
    };
    auto dis = [&](uint64_t addr) -> PcodeInsn {
        PcodeInsn pi;
        std::string e;
        if (!eng.disassemble(read, addr, pi, e))
            std::printf("disasm failed at %#llx: %s\n",
                        static_cast<unsigned long long>(addr), e.c_str());
        return pi;
    };

    // ---- disassembly of known encodings (objdump-verified) ----
    put(0x00, 0x00C58533); // add a0, a1, a2
    put(0x04, 0x00D00513); // addi a0, zero, 13
    put(0x08, 0x00008067); // ret  (jalr x0, ra, 0)
    put(0x0C, 0x00000073); // ecall
    put(0x10, 0x00B50463); // beq a0, a1, +8  (0x10+4+8 = 0x1c)
    put(0x14, 0x02B5053B); // mulw a0, a0, a1
    put(0x18, 0x0000006F); // jal zero, 0     (target 0x1c)
    put(0x1C, 0x008000EF); // jal ra, +8      (target 0x24)

    auto expect = [&](uint64_t addr, const char* what, const std::string& got,
                      const std::string& want) {
        if (got != want)
            std::printf("FAIL: %s: got \"%s\" want \"%s\"\n", what,
                        got.c_str(), want.c_str());
    };
    {
        auto pi = dis(0x00);
        expect(0, "add text", pi.text, "add a0, a1, a2");
        CHECK(pi.size == 4, "add size");
        CHECK(pi.kind == Insn::OTHER, "add kind");
    }
    {
        auto pi = dis(0x04);
        expect(0, "addi text", pi.text, "addi a0, zero, 13");
    }
    {
        auto pi = dis(0x08);
        expect(0, "ret text", pi.text, "ret");
        CHECK(pi.kind == Insn::RET, "ret kind");
    }
    {
        auto pi = dis(0x0C);
        expect(0, "ecall text", pi.text, "ecall");
    }
    {
        auto pi = dis(0x10);
        expect(0, "beq text", pi.text, "beq a0, a1, 0x1c");
        CHECK(pi.kind == Insn::JCC, "beq kind");
        CHECK(pi.targetKnown && pi.target == 0x1C, "beq target");
    }
    {
        auto pi = dis(0x14);
        expect(0, "mulw text", pi.text, "mulw a0, a0, a1");
    }
    {
        auto pi = dis(0x18);
        CHECK(pi.kind == Insn::JMP && pi.targetKnown && pi.target == 0x1C,
              "jal zero,0 target");
    }
    {
        auto pi = dis(0x1C);
        CHECK(pi.kind == Insn::CALL && pi.targetKnown && pi.target == 0x28,
              "jal ra,8 -> call 0x28");
        expect(0, "jal ra text", pi.text, "call 0x28");
    }

    // ---- p-code interpreter semantics ----
    {
        // add a0, a1, a2 with a1=3, a2=4 -> a0=7
        PcodeInsn pi = dis(0x00);
        PcodeEvaluator ev(pi);
        ev.regs[11 * 8] = 3; // a1
        ev.regs[12 * 8] = 4; // a2
        ev.run();
        auto v = ev.regValue(10 * 8); // a0
        CHECK(v.has_value() && *v == 7, "add semantics: 3+4=7");
    }
    {
        // addi a0, zero, -1 -> a0 = 0xffffffffffffffff
        put(0x20, 0xFFF00513);
        PcodeInsn pi = dis(0x20);
        expect(0, "addi -1 text", pi.text, "addi a0, zero, -1");
        PcodeEvaluator ev(pi);
        ev.regs[0] = 0; // zero
        ev.run();
        auto v = ev.regValue(10 * 8);
        CHECK(v.has_value() && *v == 0xFFFFFFFFFFFFFFFFULL,
              "addi -1 semantics: sign extension");
    }
    {
        // mulw a0, a0, a1: 0x100000000 * 2 -> low 32 bits -> sext -> 0
        PcodeInsn pi = dis(0x14);
        PcodeEvaluator ev(pi);
        ev.regs[10 * 8] = 0x100000000ULL; // a0
        ev.regs[11 * 8] = 2;              // a1
        ev.run();
        auto v = ev.regValue(10 * 8);
        CHECK(v.has_value() && *v == 0, "mulw semantics: low-32 wrap");
    }
    {
        // lw a0, 4(sp): load from ram
        put(0x24, 0x00412503);
        PcodeInsn pi = dis(0x24);
        CHECK(pi.text == "lw a0, 4(sp)", "lw text");
        PcodeEvaluator ev(pi);
        ev.regs[2 * 8] = 0x1000; // sp
        ev.ram[0x1004] = 0xAA;
        ev.ram[0x1005] = 0xBB;
        ev.ram[0x1006] = 0xCC;
        ev.ram[0x1007] = 0xDD;
        ev.run();
        auto v = ev.regValue(10 * 8);
        CHECK(v.has_value() && *v == 0xFFFFFFFFDDCCBBAAULL,
              "lw semantics (sign-extended)");
    }
    {
        // sw a1, 8(sp): store to ram
        put(0x28, 0x00B12423);
        PcodeInsn pi = dis(0x28);
        expect(0, "sw text", pi.text, "sw a1, 8(sp)");
        PcodeEvaluator ev(pi);
        ev.regs[2 * 8] = 0x2000;    // sp
        ev.regs[11 * 8] = 0x11223344; // a1
        ev.run();
        CHECK(ev.ram[0x2008] == 0x44 && ev.ram[0x200B] == 0x11,
              "sw semantics");
    }

    if (failures == 0) {
        std::printf("test_sleigh: ALL PASSED\n");
        return 0;
    }
    std::printf("test_sleigh: %d FAILURES\n", failures);
    return 1;
}
