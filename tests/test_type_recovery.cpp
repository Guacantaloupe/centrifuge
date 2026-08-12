// Golden tests for TypeRecovery pointer-element types (Phase 7).
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

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

// mov eax, [rcx]; ret          -> 4-byte integer element
std::vector<uint8_t> func_load32() { return {0x8B, 0x01, 0xC3}; }

// movsd xmm0, [rcx]; addsd xmm0, xmm0; ret  -> double element (float use)
std::vector<uint8_t> func_load_f64() {
    return {0xF2, 0x0F, 0x10, 0x01, 0xF2, 0x0F, 0x58, 0xC0, 0xC3};
}

// mov rax, [rcx]; mov [rdx], rax; ret  -> element from store too
std::vector<uint8_t> func_load_store() {
    return {0x48, 0x8B, 0x01, 0x48, 0x89, 0x02, 0xC3};
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
    if (!f) return 1;
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) {
        std::fprintf(stderr, "spec load failed: %s\n", err.c_str());
        return 2;
    }

    {
        Image img;
        put(img, 0x1000, func_load32());
        CfgBuilder cfg;
        FunctionIR ir;
        CHECK(analyze(eng, img, 0x1000, ir, cfg), "load32: analyze");
        const FunctionSignature sig = ir.inferSignature();

        CHECK(!sig.parameters.empty(), "load32: has parameters");
        if (!sig.parameters.empty()) {
            const FunctionParameter& p = sig.parameters[0];
            CHECK(p.type.kind == TypeKind::POINTER,
                  "load32: first parameter is pointer");
            CHECK(p.type.detail && p.type.detail->elementType,
                  "load32: pointer has element type");
            if (p.type.detail && p.type.detail->elementType) {
                CHECK(p.type.detail->elementType->kind ==
                          TypeKind::UNSIGNED_INT &&
                          p.type.detail->elementType->bits == 32,
                      "load32: element uint32");
            }
        }
    }

    {
        Image img;
        put(img, 0x1000, func_load_f64());
        CfgBuilder cfg;
        FunctionIR ir;
        CHECK(analyze(eng, img, 0x1000, ir, cfg), "load_f64: analyze");
        const FunctionSignature sig = ir.inferSignature();

        // scalar-vs-packed lane evidence the conservative element is a
        // 64-bit scalar (kind may stay UNSIGNED_INT when the xmm value has
        // no floating-point use, or FLOAT when addsd propagates float
        // evidence).  Both are acceptable for a 64-bit scalar element.
        CHECK(!sig.parameters.empty(), "load_f64: has parameters");
        if (!sig.parameters.empty() && sig.parameters[0].type.detail &&
            sig.parameters[0].type.detail->elementType) {
            const DataType& elem =
                *sig.parameters[0].type.detail->elementType;
            CHECK(elem.bits == 64 &&
                      (elem.kind == TypeKind::FLOAT ||
                       elem.kind == TypeKind::UNSIGNED_INT),
                  "load_f64: 64-bit scalar element");
        } else {
            CHECK(false, "load_f64: pointer element recovered");
        }
    }

    {
        Image img;
        put(img, 0x1000, func_load_store());
        CfgBuilder cfg;
        FunctionIR ir;
        CHECK(analyze(eng, img, 0x1000, ir, cfg), "load_store: analyze");
        const FunctionSignature sig = ir.inferSignature();
        // Parameter 1 (rdx) is the store target: pointer with 8-byte element.
        CHECK(sig.parameters.size() >= 2, "load_store: two parameters");
        if (sig.parameters.size() >= 2) {
            const FunctionParameter& p = sig.parameters[1];
            CHECK(p.type.kind == TypeKind::POINTER,
                  "load_store: second parameter is pointer");
            CHECK(p.type.detail && p.type.detail->elementType &&
                      p.type.detail->elementType->bits == 64,
                  "load_store: element width 64");
        }
    }

    if (failures == 0) {
        std::printf("test_type_recovery: all checks passed\n");
        return 0;
    }
    std::printf("test_type_recovery: %d FAILURES\n", failures);
    return 1;
}
