// Golden tests for CallingConventionRecovery (Phase 5).
// Real x86-64 byte sequences, decoded through the sleigh engine, then
// analyzed with FunctionIR + recoverCallConvention.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/calling_convention.hpp"
#include "centrifuge/cfg.hpp"
#include "centrifuge/ir.hpp"
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
    Image() : bytes(512, 0xCC) {}
    bool read(uint64_t a, void* buf, size_t n) const {
        if (a < 0x1000 || a + n > 0x1000 + bytes.size()) return false;
        std::memcpy(buf, bytes.data() + (a - 0x1000), n);
        return true;
    }
};

void put(Image& img, uint64_t addr, const std::vector<uint8_t>& data) {
    std::memcpy(img.bytes.data() + (addr - 0x1000), data.data(), data.size());
}

// mov rax, [rsp+rdx*8+0x28]; ret
std::vector<uint8_t> func_variadic() {
    return {0x48, 0x8B, 0x44, 0xD4, 0x28, 0xC3};
}

// mov [rcx], rax; mov rax, rcx; ret
std::vector<uint8_t> func_sret() {
    return {0x48, 0x89, 0x01, 0x48, 0x89, 0xC8, 0xC3};
}

// mov eax, ecx; add eax, edx; ret
std::vector<uint8_t> func_plain() {
    return {0x8B, 0xC1, 0x03, 0xC2, 0xC3};
}

// mov rax, [rsp+0x28]; mov rdx, [rsp+0x30]; add rax, rdx; ret
std::vector<uint8_t> func_stackargs() {
    return {0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x54,
            0x24, 0x30, 0x48, 0x03, 0xC2, 0xC3};
}

bool analyze(const SleighEngine& eng, Image& img, uint64_t addr,
             FunctionIR& ir, CfgBuilder& cfg) {
    auto read = [&](uint64_t a, void* b, size_t n) { return img.read(a, b, n); };
    if (!cfg.build(eng, read, addr, addr + 0x100)) return false;
    return ir.build(cfg, "x86-64-win64", "win64");
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <x86-64.slaspec>\n", argv[0]);
        return 1;
    }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "cannot open spec %s\n", argv[1]);
        return 1;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) {
        std::fprintf(stderr, "failed to load spec %s: %s\n", argv[1],
                     err.c_str());
        return 1;
    }

    {
        // variadic-like: indexed stack access.
        Image img;
        put(img, 0x1000, func_variadic());
        CfgBuilder cfg;
        FunctionIR ir;
        CHECK(analyze(eng, img, 0x1000, ir, cfg), "variadic: analyze");
        const CallConventionFacts facts =
            recoverCallConvention(ir, cfg, "x86-64-win64");
        // Indexed stack access is itself the variadic signal; the SSA
        // stack-input map only records constant offsets.
        CHECK(facts.indexedStackAccess, "variadic: indexed stack access");
        CHECK(facts.variadic, "variadic: verdict");
        CHECK(!facts.hiddenSret, "variadic: not sret");
        FunctionSignature sig = ir.inferSignature();
        applyCallConvention(facts, sig, "x86-64-win64");
        CHECK(sig.variadic, "variadic: signature flagged");
        const std::string decl = sig.declaration("F");
        CHECK(decl.find("...") != std::string::npos,
              "variadic: declaration contains '...'");
    }

    {
        // hidden sret: store through rcx, return rcx.
        Image img;
        put(img, 0x1000, func_sret());
        CfgBuilder cfg;
        FunctionIR ir;
        CHECK(analyze(eng, img, 0x1000, ir, cfg), "sret: analyze");
        const CallConventionFacts facts =
            recoverCallConvention(ir, cfg, "x86-64-win64");
        CHECK(facts.returnsPointerArgument, "sret: returns first arg");
        CHECK(facts.writesThroughFirstArg, "sret: writes through first arg");
        CHECK(facts.hiddenSret, "sret: verdict");
        CHECK(!facts.variadic, "sret: not variadic");
        FunctionSignature sig = ir.inferSignature();
        applyCallConvention(facts, sig, "x86-64-win64");
        CHECK(sig.hiddenSret, "sret: signature flagged");
        CHECK(!sig.parameters.empty() && sig.parameters.front().name == "ret",
              "sret: first parameter named ret");
        CHECK(sig.returnType.kind == TypeKind::VOID_TYPE,
              "sret: return type void");
    }

    {
        // plain: two register args, no stack, no sret, no variadic.
        Image img;
        put(img, 0x1000, func_plain());
        CfgBuilder cfg;
        FunctionIR ir;
        CHECK(analyze(eng, img, 0x1000, ir, cfg), "plain: analyze");
        const CallConventionFacts facts =
            recoverCallConvention(ir, cfg, "x86-64-win64");
        CHECK(!facts.readsStackArguments, "plain: no stack args");
        CHECK(!facts.indexedStackAccess, "plain: no indexed access");
        CHECK(!facts.variadic, "plain: not variadic");
        CHECK(!facts.hiddenSret, "plain: not sret");
        FunctionSignature sig = ir.inferSignature();
        applyCallConvention(facts, sig, "x86-64-win64");
        CHECK(!sig.variadic && !sig.hiddenSret, "plain: signature unchanged");
        CHECK(sig.parameters.size() >= 2, "plain: two register parameters");
    }

    {
        // fixed stack arguments: two constant-offset reads.
        Image img;
        put(img, 0x1000, func_stackargs());
        CfgBuilder cfg;
        FunctionIR ir;
        CHECK(analyze(eng, img, 0x1000, ir, cfg), "stackargs: analyze");
        const CallConventionFacts facts =
            recoverCallConvention(ir, cfg, "x86-64-win64");
        CHECK(facts.readsStackArguments, "stackargs: reads stack args");
        CHECK(!facts.indexedStackAccess, "stackargs: no dynamic index");
        CHECK(!facts.variadic, "stackargs: fixed arity, not variadic");
        CHECK(facts.stackSlots.size() == 2, "stackargs: two stack slots");
        CHECK(facts.stackSlots[0].first == 40 &&
                  facts.stackSlots[1].first == 48,
              "stackargs: slots at 40 and 48");
        FunctionSignature sig = ir.inferSignature();
        applyCallConvention(facts, sig, "x86-64-win64");
        CHECK(!sig.variadic, "stackargs: signature not variadic");
        size_t stackParameters = 0;
        for (const FunctionParameter& p : sig.parameters)
            if (p.onStack) ++stackParameters;
        CHECK(stackParameters == 2, "stackargs: two stack parameters");
    }

    if (failures == 0) {
        std::printf("test_calling_convention: all checks passed\n");
        return 0;
    }
    std::printf("test_calling_convention: %d FAILURES\n", failures);
    return 1;
}
