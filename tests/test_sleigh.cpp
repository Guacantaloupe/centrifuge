// centrifuge - a Ghidra reimplementation in C++17
// tests/test_sleigh.cpp - SLEIGH-lite engine + p-code interpreter tests
//
// Usage: test_sleigh <spec.slaspec>
// Asserts disassembly of known encodings and evaluates p-code semantics.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/decompile.hpp"
#include "centrifuge/pcode.hpp"
#include "centrifuge/sleigh.hpp"

using namespace centrifuge;

static int failures = 0;

static uint32_t branchInsn(int32_t offset, uint32_t funct3 = 0) {
    const uint32_t imm = static_cast<uint32_t>(offset);
    return ((imm >> 12) & 1) << 31 | ((imm >> 5) & 0x3f) << 25 |
           (funct3 & 7) << 12 | ((imm >> 1) & 0xf) << 8 |
           ((imm >> 11) & 1) << 7 | 0x63;
}

static uint32_t jalInsn(int32_t offset, uint32_t rd = 0) {
    const uint32_t imm = static_cast<uint32_t>(offset);
    return ((imm >> 20) & 1) << 31 | ((imm >> 1) & 0x3ff) << 21 |
           ((imm >> 11) & 1) << 20 | ((imm >> 12) & 0xff) << 12 |
           (rd & 0x1f) << 7 | 0x6f;
}

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

    auto expect = [&](const char* what, const std::string& got,
                      const std::string& want) {
        if (got != want)
            std::printf("FAIL: %s: got \"%s\" want \"%s\"\n", what,
                        got.c_str(), want.c_str());
    };
    {
        auto pi = dis(0x00);
        expect("add text", pi.text, "add a0, a1, a2");
        CHECK(pi.size == 4, "add size");
        CHECK(pi.kind == Insn::OTHER, "add kind");
    }
    {
        auto pi = dis(0x04);
        expect("addi text", pi.text, "addi a0, zero, 13");
    }
    {
        auto pi = dis(0x08);
        expect("ret text", pi.text, "ret");
        CHECK(pi.kind == Insn::RET, "ret kind");
    }
    {
        auto pi = dis(0x0C);
        expect("ecall text", pi.text, "ecall");
    }
    {
        auto pi = dis(0x10);
        expect("beq text", pi.text, "beq a0, a1, 0x18");
        CHECK(pi.kind == Insn::JCC, "beq kind");
        CHECK(pi.targetKnown && pi.target == 0x18, "beq target");
    }
    {
        auto pi = dis(0x14);
        expect("mulw text", pi.text, "mulw a0, a0, a1");
    }
    {
        auto pi = dis(0x18);
        CHECK(pi.kind == Insn::JMP && pi.targetKnown && pi.target == 0x18,
              "jal zero,0 target (self)");
    }
    {
        auto pi = dis(0x1C);
        CHECK(pi.kind == Insn::CALL && pi.targetKnown && pi.target == 0x24,
              "jal ra,8 -> call 0x24");
        expect("jal ra text", pi.text, "call 0x24");
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
        expect("addi -1 text", pi.text, "addi a0, zero, -1");
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
        expect("sw text", pi.text, "sw a1, 8(sp)");
        PcodeEvaluator ev(pi);
        ev.regs[2 * 8] = 0x2000;    // sp
        ev.regs[11 * 8] = 0x11223344; // a1
        ev.run();
        CHECK(ev.ram[0x2008] == 0x44 && ev.ram[0x200B] == 0x11,
              "sw semantics");
    }
    {
        // Signed comparisons must use the input width, not the 1-byte result.
        PcodeInsn pi;
        pi.varnodes.emplace(1, Varnode{1, Varnode::CONST, 0xFFFFFFFF, 4, {}});
        pi.varnodes.emplace(2, Varnode{2, Varnode::CONST, 1, 4, {}});
        pi.varnodes.emplace(3, Varnode{3, Varnode::UNIQUE, 0, 1, {}});
        pi.ops.push_back(PcodeOp{POp::INT_SLESS, 3, 1, 2, 0});
        PcodeEvaluator ev(pi);
        ev.run();
        auto v = ev.varnodeValue(3);
        CHECK(v.has_value() && *v == 1, "signed less: -1 < 1");
    }
    {
        // SUBPIECE(value, 2) extracts two bytes starting at byte offset 2.
        PcodeInsn pi;
        pi.varnodes.emplace(1, Varnode{1, Varnode::CONST,
                                      0x1122334455667788ULL, 8, {}});
        pi.varnodes.emplace(2, Varnode{2, Varnode::CONST, 2, 8, {}});
        pi.varnodes.emplace(3, Varnode{3, Varnode::UNIQUE, 0, 2, {}});
        pi.ops.push_back(PcodeOp{POp::SUBPIECE, 3, 1, 2, 0});
        PcodeEvaluator ev(pi);
        ev.run();
        auto v = ev.varnodeValue(3);
        CHECK(v.has_value() && *v == 0x5566, "subpiece offset and width");
    }
    {
        // Signed remainder overflow follows p-code/ISA wrap semantics.
        PcodeInsn pi;
        pi.varnodes.emplace(1, Varnode{1, Varnode::CONST, 0x8000000000000000ULL,
                                      8, {}});
        pi.varnodes.emplace(2, Varnode{2, Varnode::CONST, ~0ULL, 8, {}});
        pi.varnodes.emplace(3, Varnode{3, Varnode::UNIQUE, 0, 8, {}});
        pi.ops.push_back(PcodeOp{POp::INT_SREM, 3, 1, 2, 0});
        PcodeEvaluator ev(pi);
        ev.run();
        auto v = ev.varnodeValue(3);
        CHECK(v.has_value() && *v == 0, "signed remainder overflow");
    }

    // ---- compressed (C ext) - c.li, c.jr ra, c.addw, c.lwsp/c.swsp ----
    put(0x30, 0x4535); // c.li a0, 13        (0x4535)
    put(0x32, 0x8082); // c.jr ra            (ret)
    put(0x34, 0x9D2D); // c.addw a0, a1      (0x9d2d)
    put(0x36, 0x1141); // c.addi sp, -16     (0x1141)
    put(0x38, 0xC62A); // c.swsp a0, 12(sp)  (0xc62a)
    put(0x3A, 0x4502); // c.lwsp a0, 0(sp)   (0x4502)
    {
        auto pi = dis(0x30);
        expect("c.li text", pi.text, "c.li a0, 13");
        CHECK(pi.size == 2, "c.li size");
    }
    {
        auto pi = dis(0x32);
        expect("c.jr ra text", pi.text, "ret");
        CHECK(pi.kind == Insn::RET, "c.jr ra kind");
    }
    {
        auto pi = dis(0x34);
        expect("c.addw text", pi.text, "c.addw a0, a1");
    }
    {
        auto pi = dis(0x36);
        expect("c.addi sp text", pi.text, "c.addi sp, -16");
        PcodeEvaluator ev(pi);
        ev.regs[2 * 8] = 0x1000;
        ev.run();
        auto v = ev.regValue(2 * 8);
        CHECK(v.has_value() && *v == 0xFF0, "c.addi sp semantics");
    }
    {
        auto pi = dis(0x38);
        expect("c.swsp text", pi.text, "c.swsp a0, 12(sp)");
        PcodeEvaluator ev(pi);
        ev.regs[2 * 8] = 0x2000;
        ev.regs[10 * 8] = 0x11223344;
        ev.run();
        CHECK(ev.ram[0x200C] == 0x44 && ev.ram[0x200F] == 0x11,
              "c.swsp semantics");
    }
    {
        auto pi = dis(0x3A);
        expect("c.lwsp text", pi.text, "c.lwsp a0, 0(sp)");
    }
    {
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0x18, 0), "cfg self-jump build");
        const CfgBlock* b = cfg.blockAt(0x18);
        CHECK(b && b->succs.size() == 1 && b->succs[0] == 0x18,
              "cfg records unconditional jump successor");
    }
    // ---- CFG recovery: late leaders, joins, loops, calls and bounds ----
    img.resize(0x100, 0);
    constexpr uint32_t NOP = 0x00000013;
    constexpr uint32_t RET = 0x00008067;
    {
        // A backward branch discovers 0x44 after the linear run started at
        // 0x40. The first block must be retroactively split at that leader.
        put(0x40, NOP);
        put(0x44, NOP);
        put(0x48, branchInsn(-4));
        put(0x4c, RET);
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0x40, 0x50), "cfg late-leader build");
        const CfgBlock* entry = cfg.blockAt(0x40);
        const CfgBlock* loop = cfg.blockAt(0x44);
        CHECK(entry && entry->insns.size() == 1 && entry->succs ==
                  std::vector<uint64_t>{0x44},
              "cfg splits an existing run at a late leader");
        CHECK(loop && loop->insns.size() == 2 && loop->succs.size() == 2,
              "cfg preserves branch after late split");
    }
    {
        // Diamond: both arms join at 0x70.
        put(0x60, branchInsn(12));
        put(0x64, NOP);
        put(0x68, jalInsn(8));
        put(0x6c, NOP);
        put(0x70, RET);
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0x60, 0x74), "cfg diamond build");
        CHECK(cfg.loops().empty(), "diamond CFG has no natural loop");
        CHECK(cfg.predecessors(0x70) == std::set<uint64_t>({0x64, 0x6c}),
              "cfg records both diamond predecessors");
        const auto dom = cfg.dominators(0x70);
        CHECK(dom == std::set<uint64_t>({0x60, 0x70}),
              "cfg computes diamond dominators");
    }
    {
        // Natural loop with a back edge and a return fallthrough.
        put(0x80, NOP);
        put(0x84, branchInsn(-4, 1)); // bne zero,zero,0x80
        put(0x88, RET);
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0x80, 0x8c), "cfg loop build");
        const CfgBlock* loop = cfg.blockAt(0x80);
        CHECK(loop && loop->succs == std::vector<uint64_t>({0x88, 0x80}),
              "cfg records loop fallthrough and back edge");
        CHECK(cfg.predecessors(0x80) == std::set<uint64_t>({0x80}),
              "cfg records loop self predecessor");
        const NaturalLoop* natural = cfg.loopByHeader(0x80);
        const std::vector<std::pair<uint64_t, uint64_t>> expectedBackEdges = {
            {0x80, 0x80}};
        const std::vector<std::pair<uint64_t, uint64_t>> expectedExits = {
            {0x80, 0x88}};
        CHECK(natural && natural->blocks == std::set<uint64_t>({0x80}) &&
                  natural->backEdges == expectedBackEdges &&
                  natural->exits == expectedExits,
              "cfg detects single-block natural loop and exit");
        const auto nameOf = [](uint64_t) { return std::string("target"); };
        const std::string text = decompile(eng, read, 0x80, 0x8c, nameOf);
        CHECK(text.find("do {") != std::string::npos &&
                  text.find("} while (") != std::string::npos,
              "decompiler structures a single-block do-while loop");
    }
    {
        // An unreadable direct target must not expand the graph.
        put(0xa0, jalInsn(0x100));
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0xa0, 0), "cfg invalid-target build");
        const CfgBlock* block = cfg.blockAt(0xa0);
        CHECK(block && block->succs.empty() && cfg.blocks().size() == 1,
              "cfg rejects unreadable jump targets");
    }
    {
        // A readable address rejected by the executable validator is excluded.
        put(0xb0, jalInsn(0x30)); // target 0xe0 is readable
        CfgBuilder cfg;
        auto executable = [](uint64_t addr) { return addr == 0xb0; };
        CHECK(cfg.build(eng, read, 0xb0, 0, executable),
              "cfg executable-validator build");
        const CfgBlock* block = cfg.blockAt(0xb0);
        CHECK(block && block->succs.empty() && cfg.blockAt(0xe0) == nullptr,
              "cfg rejects non-executable jump targets");
    }
    {
        // A direct jump outside an explicit function range is a tail call.
        put(0xc0, jalInsn(0x20));
        put(0xe0, RET);
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0xc0, 0xc4), "cfg tail-call build");
        const CfgBlock* block = cfg.blockAt(0xc0);
        CHECK(block && block->isTailCall() &&
                  *block->tailCallTarget == 0xe0 && block->succs.empty(),
              "cfg recognizes bounded direct tail call");
    }
    {
        // Calls are metadata edges; control flow continues after the call.
        put(0xd0, jalInsn(0x10, 1));
        put(0xd4, RET);
        put(0xd8, NOP); // unreachable after return
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0xd0, 0xdc), "cfg call build");
        const CfgBlock* block = cfg.blockAt(0xd0);
        CHECK(block && block->calls == std::vector<uint64_t>({0xe0}) &&
                  block->insns.size() == 2,
              "cfg records call edge and continues to return");
        CHECK(cfg.blockAt(0xd8) == nullptr, "cfg excludes unreachable code");
    }
    {
        // Nested loops: 0x104 is contained by the outer loop at 0x100.
        img.resize(0x180, 0);
        put(0x100, branchInsn(0x24)); // outer exit -> 0x124
        put(0x104, branchInsn(0x10)); // inner exit -> 0x114
        put(0x108, NOP);
        put(0x10c, jalInsn(-8));      // inner back edge -> 0x104
        put(0x114, NOP);
        put(0x118, jalInsn(-0x18));   // outer back edge -> 0x100
        put(0x124, RET);
        CfgBuilder cfg;
        CHECK(cfg.build(eng, read, 0x100, 0x128), "cfg nested-loop build");
        const NaturalLoop* outer = cfg.loopByHeader(0x100);
        const NaturalLoop* inner = cfg.loopByHeader(0x104);
        CHECK(outer && inner && inner->parentHeader == 0x100,
              "cfg records nested-loop parent");
        CHECK(outer && outer->blocks ==
                  std::set<uint64_t>({0x100, 0x104, 0x108, 0x114}),
              "cfg collects outer natural-loop body");
        CHECK(inner && inner->blocks == std::set<uint64_t>({0x104, 0x108}),
              "cfg collects inner natural-loop body");
        const NaturalLoop* owner = cfg.innermostLoopForBlock(0x108);
        CHECK(owner && owner->header == 0x104,
              "cfg returns innermost loop for a block");
    }
    {
        // Canonical condition header + body back edge -> while loop.
        put(0x140, branchInsn(0x10)); // exit -> 0x150, fall into body
        put(0x144, NOP);
        put(0x148, jalInsn(-8));      // back edge -> 0x140
        put(0x150, RET);
        const auto nameOf = [](uint64_t) { return std::string("target"); };
        const std::string text = decompile(eng, read, 0x140, 0x154, nameOf);
        CHECK(text.find("while (") != std::string::npos &&
                  text.find("goto L0x140") == std::string::npos,
              "decompiler structures a canonical while loop");
    }
    {
        put(0x160, jalInsn(0)); // unconditional self loop
        const auto nameOf = [](uint64_t) { return std::string("target"); };
        const std::string text = decompile(eng, read, 0x160, 0x164, nameOf);
        CHECK(text.find("while (1)") != std::string::npos,
              "decompiler structures an infinite loop");
    }

    if (failures == 0) {
        std::printf("test_sleigh: ALL PASSED\n");
        return 0;
    }
    std::printf("test_sleigh: %d FAILURES\n", failures);
    return 1;
}
