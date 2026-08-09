// x86 flag, condition-code, and conditional-move semantic tests.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <cmath>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/pcode.hpp"
#include "centrifuge/sleigh.hpp"

using namespace centrifuge;

namespace {

int failures = 0;

#define CHECK(cond, msg)                                            \
    do {                                                            \
        if (!(cond)) {                                              \
            std::printf("FAIL: %s\n", msg);                        \
            ++failures;                                             \
        }                                                           \
    } while (0)

constexpr uint64_t RAX = 0;
constexpr uint64_t RBX = 3 * 8;
constexpr uint64_t RCX = 1 * 8;
constexpr uint64_t CF = 4096;
constexpr uint64_t PF = 4097;
constexpr uint64_t AF = 4098;
constexpr uint64_t ZF = 4099;
constexpr uint64_t SF = 4100;
constexpr uint64_t OF = 4101;

void checkReg(PcodeEvaluator& ev, uint64_t offset, uint64_t want,
              const char* message) {
    const auto got = ev.regValue(offset);
    if (!got.has_value() || *got != want) {
        std::printf("FAIL: %s (got %s%llu, want %llu)\n", message,
                    got ? "" : "unknown/", static_cast<unsigned long long>(got.value_or(0)),
                    static_cast<unsigned long long>(want));
        ++failures;
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: test_x86_flags <x86-64.slaspec>\n");
        return 2;
    }

    std::ifstream spec(argv[1]);
    std::ostringstream source;
    source << spec.rdbuf();
    SleighEngine engine;
    std::string error;
    if (!spec || !engine.loadSpec(source.str(), error)) {
        std::fprintf(stderr, "x86 spec load failed: %s\n", error.c_str());
        return 2;
    }

    std::vector<uint8_t> image(512, 0x90);
    auto put = [&](size_t at, std::initializer_list<uint8_t> bytes) {
        size_t i = at;
        for (uint8_t byte : bytes) image[i++] = byte;
    };
    put(0x00, {0x48, 0x39, 0xD8});       // cmp rax, rbx
    put(0x10, {0x48, 0x01, 0xD8});       // add rax, rbx
    put(0x20, {0x48, 0x31, 0xC0});       // xor rax, rax
    put(0x30, {0x74, 0x05});             // je +5
    put(0x40, {0x0F, 0x9C, 0xC0});       // setl al
    put(0x50, {0x48, 0x0F, 0x4F, 0xC3}); // cmovg rax, rbx
    put(0x60, {0x48, 0xFF, 0xC0});       // inc rax
    put(0x70, {0x48, 0xD1, 0xE0});       // shl rax, 1
    put(0x80, {0x0F, 0x85, 0x05, 0, 0, 0}); // jne +5 (near)
    put(0x90, {0x48, 0x39, 0x18});       // cmp [rax], rbx
    put(0xA0, {0x48, 0x11, 0xD8});       // adc rax, rbx
    put(0xB0, {0x48, 0x19, 0xD8});       // sbb rax, rbx
    put(0xC0, {0x48, 0xC1, 0xE0, 0x00}); // shl rax, 0
    put(0xD0, {0x0F, 0x58, 0xC1});       // addps xmm0, xmm1
    put(0xE0, {0x0F, 0x2E, 0xC1});       // ucomiss xmm0, xmm1
    put(0xF0, {0xF3, 0x0F, 0x58, 0xC1}); // addss xmm0, xmm1
    put(0x100, {0x48, 0xD1, 0xC0});      // rol rax, 1
    put(0x110, {0x48, 0xD1, 0xC8});      // ror rax, 1
    put(0x120, {0x48, 0x0F, 0xA3, 0xD8}); // bt rax, rbx
    put(0x130, {0x48, 0x0F, 0xB3, 0xD8}); // btr rax, rbx
    put(0x140, {0xF3, 0x48, 0x0F, 0xB8, 0xC3}); // popcnt rax, rbx
    put(0x150, {0x48, 0x0F, 0xBC, 0xC3}); // bsf rax, rbx
    put(0x160, {0x48, 0x0F, 0xAF, 0xC3}); // imul rax, rbx
    put(0x170, {0x48, 0x0F, 0xC1, 0xD8}); // xadd rax, rbx
    put(0x180, {0x66, 0x0F, 0x6F, 0xC1}); // movdqa xmm0, xmm1
    put(0x190, {0x66, 0x0F, 0xFE, 0xC1}); // paddd xmm0, xmm1
    put(0x1A0, {0x66, 0x0F, 0xEF, 0xC1}); // pxor xmm0, xmm1
    put(0x1B0, {0xF3, 0x0F, 0x2A, 0xC3}); // cvtsi2ss xmm0, ebx
    put(0x1C0, {0xF3, 0x48, 0x0F, 0x2C, 0xC1}); // cvttss2si rax, xmm1
    put(0x1D0, {0xF3, 0x0F, 0x5A, 0xC1}); // cvtss2sd xmm0, xmm1
    put(0x1E0, {0x48, 0x0F, 0xA4, 0xD8, 0x01}); // shld rax, rbx, 1
    put(0x1F0, {0x48, 0x0F, 0xAC, 0xD8, 0x01}); // shrd rax, rbx, 1

    auto read = [&](uint64_t address, void* dst, size_t size) {
        if (address > image.size() || size > image.size() - address) return false;
        std::memcpy(dst, image.data() + address, size);
        return true;
    };
    auto disassemble = [&](uint64_t address) {
        PcodeInsn insn;
        std::string err;
        if (!engine.disassemble(read, address, insn, err)) {
            std::printf("FAIL: disassembly at %#llx: %s\n",
                        static_cast<unsigned long long>(address), err.c_str());
            ++failures;
        }
        return insn;
    };

    {
        PcodeEvaluator ev(disassemble(0x00));
        ev.regs[RAX] = 5;
        ev.regs[RBX] = 5;
        ev.run();
        checkReg(ev, CF, 0, "cmp equal clears CF");
        checkReg(ev, PF, 1, "cmp zero result has even parity");
        checkReg(ev, AF, 0, "cmp equal clears AF");
        checkReg(ev, ZF, 1, "cmp equal sets ZF");
        checkReg(ev, SF, 0, "cmp equal clears SF");
        checkReg(ev, OF, 0, "cmp equal clears OF");
        checkReg(ev, RAX, 5, "cmp does not modify destination");
    }
    {
        PcodeEvaluator ev(disassemble(0x00));
        ev.regs[RAX] = 0;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, CF, 1, "cmp borrow sets CF");
        checkReg(ev, PF, 1, "0xff has even parity");
        checkReg(ev, AF, 1, "cmp low-nibble borrow sets AF");
        checkReg(ev, ZF, 0, "nonzero cmp clears ZF");
        checkReg(ev, SF, 1, "negative cmp sets SF");
        checkReg(ev, OF, 0, "zero minus one has no signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0x00));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, OF, 1, "signed subtraction overflow sets OF");
        checkReg(ev, SF, 0, "overflowed subtraction result is positive");
    }
    {
        PcodeEvaluator ev(disassemble(0x10));
        ev.regs[RAX] = ~0ULL;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, RAX, 0, "64-bit add wraps");
        checkReg(ev, CF, 1, "add carry sets CF");
        checkReg(ev, AF, 1, "add nibble carry sets AF");
        checkReg(ev, ZF, 1, "wrapped add sets ZF");
        checkReg(ev, PF, 1, "wrapped add sets PF");
    }
    {
        PcodeEvaluator ev(disassemble(0x20));
        ev.regs[RAX] = 0x1234;
        ev.run();
        checkReg(ev, RAX, 0, "xor self produces zero");
        checkReg(ev, CF, 0, "logical operation clears CF");
        checkReg(ev, OF, 0, "logical operation clears OF");
        checkReg(ev, ZF, 1, "xor zero sets ZF");
    }
    {
        PcodeInsn insn = disassemble(0x30);
        CHECK(insn.kind == Insn::JCC && insn.targetKnown && insn.target == 0x37,
              "short je target and classification");
        PcodeEvaluator yes(insn);
        yes.regs[ZF] = 1;
        yes.run();
        CHECK(yes.branchTaken(), "je is taken when ZF=1");
        PcodeEvaluator no(insn);
        no.regs[ZF] = 0;
        no.run();
        CHECK(!no.branchTaken(), "je is not taken when ZF=0");
    }
    {
        PcodeInsn insn = disassemble(0x80);
        CHECK(insn.kind == Insn::JCC && insn.targetKnown && insn.target == 0x8B,
              "near jne target and classification");
        PcodeEvaluator ev(insn);
        ev.regs[ZF] = 0;
        ev.run();
        CHECK(ev.branchTaken(), "near jne consumes ZF");
    }
    {
        PcodeEvaluator yes(disassemble(0x40));
        yes.regs[SF] = 1;
        yes.regs[OF] = 0;
        yes.run();
        checkReg(yes, RAX, 1, "setl writes one when SF differs from OF");
        PcodeEvaluator no(disassemble(0x40));
        no.regs[SF] = 1;
        no.regs[OF] = 1;
        no.run();
        checkReg(no, RAX, 0, "setl writes zero when SF equals OF");
    }
    {
        PcodeInsn insn = disassemble(0x50);
        PcodeEvaluator yes(insn);
        yes.regs[RAX] = 10;
        yes.regs[RBX] = 20;
        yes.regs[ZF] = 0;
        yes.regs[SF] = 0;
        yes.regs[OF] = 0;
        yes.run();
        checkReg(yes, RAX, 20, "cmovg copies source when condition is true");
        PcodeEvaluator no(insn);
        no.regs[RAX] = 10;
        no.regs[RBX] = 20;
        no.regs[ZF] = 1;
        no.regs[SF] = 0;
        no.regs[OF] = 0;
        no.run();
        checkReg(no, RAX, 10, "cmovg preserves destination when false");
    }
    {
        PcodeEvaluator ev(disassemble(0x60));
        ev.regs[RAX] = 0x7fffffffffffffffULL;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL, "inc updates destination");
        checkReg(ev, CF, 1, "inc preserves CF");
        checkReg(ev, OF, 1, "inc sets signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0x70));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[CF] = 0;
        ev.run();
        checkReg(ev, RAX, 0, "shl shifts destination");
        checkReg(ev, CF, 1, "shl exposes shifted-out bit in CF");
        checkReg(ev, OF, 1, "single-bit shl updates OF");
        checkReg(ev, ZF, 1, "shl zero result sets ZF");
    }
    {
        PcodeEvaluator ev(disassemble(0x90));
        ev.regs[RAX] = 0x120;
        ev.regs[RBX] = 7;
        for (int i = 0; i < 8; ++i)
            ev.ram[0x120 + i] = static_cast<uint8_t>(i == 0 ? 7 : 0);
        ev.run();
        checkReg(ev, ZF, 1, "memory cmp computes flags from loaded value");
        CHECK(ev.ram[0x120] == 7 && ev.ram[0x127] == 0,
              "memory cmp never writes its operand");
    }
    {
        PcodeEvaluator ev(disassemble(0xA0));
        ev.regs[RAX] = ~0ULL;
        ev.regs[RBX] = 0;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0, "adc includes incoming CF");
        checkReg(ev, CF, 1, "adc reports carry from incoming CF");
        checkReg(ev, ZF, 1, "adc result updates ZF");
    }
    {
        PcodeEvaluator ev(disassemble(0xA0));
        ev.regs[RAX] = 0;
        ev.regs[RBX] = 0x7fffffffffffffffULL;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "adc crosses the signed-positive boundary with carry-in");
        checkReg(ev, OF, 1, "adc includes carry-in in signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0xA0));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = ~0ULL;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "adc handles an overflowing intermediate add");
        checkReg(ev, OF, 0,
                 "adc cancels intermediate overflow when carry restores INT_MIN");
    }
    {
        PcodeEvaluator ev(disassemble(0xB0));
        ev.regs[RAX] = 0;
        ev.regs[RBX] = 0;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, ~0ULL, "sbb includes incoming CF");
        checkReg(ev, CF, 1, "sbb reports borrow from incoming CF");
        checkReg(ev, SF, 1, "sbb negative result updates SF");
    }
    {
        PcodeEvaluator ev(disassemble(0xB0));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = 0;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x7fffffffffffffffULL,
                 "sbb crosses the signed-negative boundary with borrow-in");
        checkReg(ev, OF, 1, "sbb includes borrow-in in signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0xC0));
        ev.regs[RAX] = 0x1234;
        ev.regs[CF] = 1;
        ev.regs[PF] = 0;
        ev.regs[ZF] = 1;
        ev.regs[SF] = 1;
        ev.regs[OF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x1234, "zero-count shift preserves destination");
        checkReg(ev, CF, 1, "zero-count shift preserves CF");
        checkReg(ev, PF, 0, "zero-count shift preserves PF");
        checkReg(ev, ZF, 1, "zero-count shift preserves ZF");
        checkReg(ev, SF, 1, "zero-count shift preserves SF");
        checkReg(ev, OF, 1, "zero-count shift preserves OF");
    }
    {
        PcodeInsn insn = disassemble(0xD0);
        PcodeEvaluator ev(insn);
        const float left[4] = {1, 2, 3, 4};
        const float right[4] = {10, 20, 30, 40};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, 16);
        std::memcpy(ev.wideRegs[8].data(), right, 16);
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        CHECK(result && result->size() == 16, "packed float result is 128 bits");
        float lanes[4] = {};
        if (result) std::memcpy(lanes, result->data(), 16);
        CHECK(lanes[0] == 11 && lanes[1] == 22 && lanes[2] == 33 && lanes[3] == 44,
              "addps evaluates every float lane");
    }
    {
        PcodeInsn insn = disassemble(0xE0);
        PcodeEvaluator ev(insn);
        const float left[4] = {1, 0, 0, 0};
        const float right[4] = {2, 0, 0, 0};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, 16);
        std::memcpy(ev.wideRegs[8].data(), right, 16);
        ev.run();
        checkReg(ev, CF, 1, "ucomiss less-than sets CF");
        checkReg(ev, PF, 0, "ordered ucomiss clears PF");
        checkReg(ev, ZF, 0, "unequal ucomiss clears ZF");
    }
    {
        PcodeInsn insn = disassemble(0xF0);
        PcodeEvaluator ev(insn);
        const float left[4] = {1, 7, 8, 9};
        const float right[4] = {2, 20, 30, 40};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, 16);
        std::memcpy(ev.wideRegs[8].data(), right, 16);
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        float lanes[4] = {};
        if (result) std::memcpy(lanes, result->data(), 16);
        CHECK(lanes[0] == 3 && lanes[1] == 7 && lanes[2] == 8 && lanes[3] == 9,
              "addss updates the low lane and preserves upper lanes");
    }
    {
        PcodeEvaluator ev(disassemble(0x100));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[CF] = 0;
        ev.regs[OF] = 0;
        ev.run();
        checkReg(ev, RAX, 1, "rol rotates the high bit into bit zero");
        checkReg(ev, CF, 1, "rol reports rotated-out bit in CF");
        checkReg(ev, OF, 1, "single-bit rol updates OF");
    }
    {
        PcodeEvaluator ev(disassemble(0x110));
        ev.regs[RAX] = 1;
        ev.regs[CF] = 0;
        ev.regs[OF] = 0;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "ror rotates bit zero into the high bit");
        checkReg(ev, CF, 1, "ror reports rotated-out bit in CF");
        checkReg(ev, OF, 1, "single-bit ror updates OF");
    }
    {
        PcodeEvaluator ev(disassemble(0x120));
        ev.regs[RAX] = 8;
        ev.regs[RBX] = 3;
        ev.run();
        checkReg(ev, CF, 1, "bt copies selected bit into CF");
        checkReg(ev, RAX, 8, "bt preserves its operand");
    }
    {
        PcodeEvaluator ev(disassemble(0x130));
        ev.regs[RAX] = 8;
        ev.regs[RBX] = 3;
        ev.run();
        checkReg(ev, CF, 1, "btr reports original selected bit");
        checkReg(ev, RAX, 0, "btr clears selected bit");
    }
    {
        PcodeEvaluator ev(disassemble(0x140));
        ev.regs[RBX] = 0xB;
        ev.run();
        checkReg(ev, RAX, 3, "popcnt counts set bits");
        checkReg(ev, ZF, 0, "popcnt clears ZF for nonzero input");
        checkReg(ev, CF, 0, "popcnt clears CF");
    }
    {
        PcodeEvaluator ev(disassemble(0x150));
        ev.regs[RAX] = 99;
        ev.regs[RBX] = 0x20;
        ev.run();
        checkReg(ev, RAX, 5, "bsf returns the least significant set-bit index");
        checkReg(ev, ZF, 0, "bsf clears ZF for nonzero input");
    }
    {
        PcodeEvaluator ev(disassemble(0x160));
        ev.regs[RAX] = 0x7fffffffffffffffULL;
        ev.regs[RBX] = 2;
        ev.run();
        checkReg(ev, RAX, 0xfffffffffffffffeULL, "imul writes truncated product");
        checkReg(ev, CF, 1, "overflowing imul sets CF");
        checkReg(ev, OF, 1, "overflowing imul sets OF");
    }
    {
        PcodeEvaluator ev(disassemble(0x170));
        ev.regs[RAX] = 3;
        ev.regs[RBX] = 4;
        ev.run();
        checkReg(ev, RAX, 7, "xadd writes sum to destination");
        checkReg(ev, RBX, 3, "xadd writes old destination to source");
        checkReg(ev, ZF, 0, "xadd updates arithmetic flags");
    }
    {
        PcodeInsn insn = disassemble(0x180);
        PcodeEvaluator ev(insn);
        const uint32_t source[4] = {1, 2, 3, 4};
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[8].data(), source, sizeof(source));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        CHECK(result && std::memcmp(result->data(), source, sizeof(source)) == 0,
              "movdqa copies the full SIMD register");
    }
    {
        PcodeInsn insn = disassemble(0x190);
        PcodeEvaluator ev(insn);
        const uint32_t left[4] = {0xffffffffU, 2, 0x80000000U, 9};
        const uint32_t right[4] = {2, 3, 0x80000000U, 4};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, sizeof(left));
        std::memcpy(ev.wideRegs[8].data(), right, sizeof(right));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        const uint32_t expected[4] = {1, 5, 0, 13};
        CHECK(result && std::memcmp(result->data(), expected, sizeof(expected)) == 0,
              "paddd wraps independently in every 32-bit lane");
    }
    {
        PcodeInsn insn = disassemble(0x1A0);
        PcodeEvaluator ev(insn);
        const uint64_t left[2] = {0xffff0000ffff0000ULL, 0xaaaaaaaaaaaaaaaaULL};
        const uint64_t right[2] = {0x00ff00ff00ff00ffULL, 0x5555555555555555ULL};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, sizeof(left));
        std::memcpy(ev.wideRegs[8].data(), right, sizeof(right));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        const uint64_t expected[2] = {left[0] ^ right[0], left[1] ^ right[1]};
        CHECK(result && std::memcmp(result->data(), expected, sizeof(expected)) == 0,
              "pxor applies to every SIMD bit");
    }
    {
        PcodeInsn insn = disassemble(0x1B0);
        PcodeEvaluator ev(insn);
        const float original[4] = {0, 7, 8, 9};
        ev.wideRegs[RAX].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), original, sizeof(original));
        ev.regs[RBX] = static_cast<uint32_t>(-7);
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        float lanes[4] = {};
        if (result) std::memcpy(lanes, result->data(), sizeof(lanes));
        CHECK(lanes[0] == -7 && lanes[1] == 7 && lanes[2] == 8 && lanes[3] == 9,
              "cvtsi2ss converts signed input and preserves upper lanes");
    }
    {
        PcodeInsn insn = disassemble(0x1C0);
        PcodeEvaluator ev(insn);
        const float source[4] = {3.9f, 0, 0, 0};
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[8].data(), source, sizeof(source));
        ev.run();
        checkReg(ev, RAX, 3, "cvttss2si truncates toward zero");
    }
    {
        PcodeInsn insn = disassemble(0x1D0);
        PcodeEvaluator ev(insn);
        const uint64_t original[2] = {0, 0x1122334455667788ULL};
        const float source[4] = {2.5f, 0, 0, 0};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), original, sizeof(original));
        std::memcpy(ev.wideRegs[8].data(), source, sizeof(source));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        double low = 0;
        uint64_t high = 0;
        if (result) {
            std::memcpy(&low, result->data(), sizeof(low));
            std::memcpy(&high, result->data() + 8, sizeof(high));
        }
        CHECK(low == 2.5 && high == original[1],
              "cvtss2sd widens the low lane and preserves the upper half");
    }
    {
        PcodeEvaluator ev(disassemble(0x1E0));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = 0;
        ev.run();
        checkReg(ev, RAX, 0, "shld shifts bits across the register pair");
        checkReg(ev, CF, 1, "shld reports the destination bit shifted out");
        checkReg(ev, OF, 1, "single-bit shld updates signed overflow");
        checkReg(ev, ZF, 1, "shld updates zero flag");
    }
    {
        PcodeEvaluator ev(disassemble(0x1F0));
        ev.regs[RAX] = 1;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "shrd shifts source bits into the destination high end");
        checkReg(ev, CF, 1, "shrd reports the destination bit shifted out");
        checkReg(ev, OF, 1, "single-bit shrd updates signed overflow");
        checkReg(ev, SF, 1, "shrd updates sign flag");
    }

    if (failures) {
        std::printf("%d x86 flag test(s) failed\n", failures);
        return 1;
    }
    std::puts("all x86 flag tests passed");
    return 0;
}
