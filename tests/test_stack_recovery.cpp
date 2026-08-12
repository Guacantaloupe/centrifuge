// centrifuge - Native Source Recovery Backend tests
// tests/test_stack_recovery.cpp
//
// Phase 1-3 golden tests: StackFrameAnalysis / StackSlotRecovery /
// VariablePromotion on hand-assembled Windows x64 functions.
//
// Verifies:
//   * prologue recovery (frame size, saved registers, frame pointer)
//   * stable stack slots are lifted and promoted to local variables
//   * parameters / return-address slots are never promoted
//   * mixed-width and address-taken slots fall back (never promoted)
//   * the Machine Semantic Backend output is unchanged without the model
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/decompile.hpp"
#include "centrifuge/sleigh.hpp"
#include "centrifuge/stack_recovery.hpp"

using namespace centrifuge;

namespace {
int failures = 0;
#define CHECK(c, m)                                                    \
    do {                                                               \
        if (!(c)) {                                                    \
            std::printf("FAIL: %s\n", m);                              \
            failures++;                                                \
        }                                                              \
    } while (0)

struct Image {
    std::vector<uint8_t> bytes; // generous padded backing store
    Image() : bytes(512, 0xCC) {}
    bool read(uint64_t a, void* buf, size_t n) const {
        if (a < 0x1000 || a + n > 0x1000 + bytes.size()) return false;
        std::memcpy(buf, bytes.data() + (a - 0x1000), n);
        return true;
    }
};

void put(Image& img, uint64_t addr, const std::vector<uint8_t>& code) {
    const uint64_t base = addr - 0x1000;
    if (base + code.size() > img.bytes.size())
        img.bytes.resize(base + code.size(), 0xCC);
    std::memcpy(img.bytes.data() + base, code.data(), code.size());
}

// ---------------------------------------------------------------------------
// Hand-assembled functions
// ---------------------------------------------------------------------------

// frame-pointer function: two promoted locals
//   push rbp; mov rbp,rsp; sub rsp,0x20
//   mov [rbp-0x14], eax; mov eax, [rbp-0x14]
//   mov [rbp-0x10], rcx; mov rax, [rbp-0x10]
//   add rsp,0x20; pop rbp; ret
std::vector<uint8_t> func_frame_ptr() {
    return {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
            0x89, 0x45, 0xEC, 0x8B, 0x45, 0xEC,
            0x48, 0x89, 0x4D, 0xF0, 0x48, 0x8B, 0x45, 0xF0,
            0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3};
}

// no frame pointer: rsp-relative locals
//   sub rsp,0x28
//   mov [rsp+0x20], ecx; mov eax, [rsp+0x20]
//   mov [rsp], eax
//   add rsp,0x28; ret
std::vector<uint8_t> func_no_fp() {
    return {0x48, 0x83, 0xEC, 0x28,
            0x89, 0x4C, 0x24, 0x20, 0x8B, 0x44, 0x24, 0x20,
            0x89, 0x04, 0x24,
            0x48, 0x83, 0xC4, 0x28, 0xC3};
}

// parameter and return-address access: never promoted
//   push rbp; mov rbp,rsp
//   mov rax, [rbp+0x10]; mov rcx, [rbp+0x8]
//   pop rbp; ret
std::vector<uint8_t> func_param() {
    return {0x55, 0x48, 0x89, 0xE5,
            0x48, 0x8B, 0x45, 0x10, 0x48, 0x8B, 0x4D, 0x08,
            0x5D, 0xC3};
}

// mixed-width access to one slot: not promoted
//   push rbp; mov rbp,rsp; sub rsp,0x18
//   mov [rbp-0x10], ecx ; mov rax, [rbp-0x10]
//   add rsp,0x18; pop rbp; ret
std::vector<uint8_t> func_mixed_width() {
    return {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x18,
            0x89, 0x4D, 0xF0, 0x48, 0x8B, 0x45, 0xF0,
            0x48, 0x83, 0xC4, 0x18, 0x5D, 0xC3};
}

// address-taken local (lea): not promoted
//   push rbp; mov rbp,rsp; sub rsp,0x20
//   lea rax, [rbp-0x10]; mov [rbp-0x10], rax
//   add rsp,0x20; pop rbp; ret
std::vector<uint8_t> func_lea() {
    return {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
            0x48, 0x8D, 0x45, 0xF0, 0x48, 0x89, 0x45, 0xF0,
            0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3};
}

// ---------------------------------------------------------------------------

bool analyzeFunction(SleighEngine& eng, const Image& img, uint64_t start,
                     const std::string& architecture,
                     StackFrameModel& model) {
    CfgBuilder cfg;
    auto read = [&](uint64_t a, void* b, size_t n) {
        return img.read(a, b, n);
    };
    if (!cfg.build(eng, read, start, start + 0x200))
        return false;
    StackFrameAnalysis analysis;
    if (!analysis.analyze(cfg, architecture)) return false;
    model = analysis.model();
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_stack_recovery <x86-64.slaspec>\n");
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

    const std::string arch = "x86-64-win64";

    const int64_t fpBias = -8; // rbp = rsp after push rbp
    const int64_t fpBiasMixed = -8 - 0x18; // push rbp + sub rsp,0x18
    const int64_t noFpBias = -0x28;

    // ---- frame-pointer function -----------------------------------------
    {
        Image img;
        put(img, 0x1000, func_frame_ptr());
        StackFrameModel model;
        CHECK(analyzeFunction(eng, img, 0x1000, arch, model),
              "frame_ptr: analyze");

        CHECK(model.frameSize == 0x28, "frame_ptr: frameSize == 0x28");
        CHECK(model.hasFramePointer, "frame_ptr: hasFramePointer");
        CHECK(model.frameBaseOffset == fpBias,
              "frame_ptr: frameBaseOffset == -8");
        CHECK(model.savedRegisters.size() == 1,
              "frame_ptr: one saved register (rbp)");

        const StackSlot* s4 = model.slotAt(-0x1c); // rbp-0x14, 4 bytes
        CHECK(s4 != nullptr, "frame_ptr: slot -0x1c present");
        if (s4) {
            CHECK(s4->promoted, "frame_ptr: slot -0x1c promoted");
            CHECK(s4->role == StackSlotRole::LOCAL,
                  "frame_ptr: slot -0x1c role LOCAL");
            CHECK(s4->typeName == "uint32_t",
                  "frame_ptr: slot -0x1c type uint32_t");
            CHECK(!s4->variableName.empty(),
                  "frame_ptr: slot -0x1c has variable name");
        }
        const StackSlot* s8 = model.slotAt(-0x18); // rbp-0x10, 8 bytes
        CHECK(s8 != nullptr, "frame_ptr: slot -0x18 present");
        if (s8) {
            CHECK(s8->promoted, "frame_ptr: slot -0x18 promoted");
            CHECK(s8->typeName == "uint64_t",
                  "frame_ptr: slot -0x18 type uint64_t");
        }
        CHECK(model.promotedCount == 2,
              "frame_ptr: exactly two promoted locals");

        // native output: locals used, no raw stack expressions
        auto read = [&](uint64_t a, void* b, size_t n) {
            return img.read(a, b, n);
        };
        const std::string native =
            decompile(eng, read, 0x1000, 0x1200, nullptr, nullptr, arch,
                      false, &model);
        CHECK(native.find(s4 ? s4->variableName : "local_m28") !=
                  std::string::npos,
              "frame_ptr: native output references promoted variable");
        CHECK(native.find("local_m28 = ") != std::string::npos,
              "frame_ptr: store emitted to promoted variable");
        CHECK(native.find("recovered_load") == std::string::npos,
              "frame_ptr: no recovered_load in native output");
        CHECK(native.find("recovered_store") == std::string::npos,
              "frame_ptr: no recovered_store in native output");
        CHECK(native.find("*(uint32_t *)(rbp") == std::string::npos,
              "frame_ptr: no raw stack dereference");

        // machine backend output is unchanged when the model is absent
        const std::string machine =
            decompile(eng, read, 0x1000, 0x1200, nullptr, nullptr, arch,
                      false, nullptr);
        CHECK(machine.find("recovered_load") == std::string::npos &&
                  machine.find("*(uint32_t *)(rbp") != std::string::npos,
              "frame_ptr: machine output keeps raw dereference");
        CHECK(machine.find(s4 ? s4->variableName : "local_m28") ==
                  std::string::npos,
              "frame_ptr: machine output does not use model variable names");
    }

    // ---- no frame pointer ------------------------------------------------
    {
        Image img;
        put(img, 0x1000, func_no_fp());
        StackFrameModel model;
        CHECK(analyzeFunction(eng, img, 0x1000, arch, model),
              "no_fp: analyze");
        CHECK(model.frameSize == noFpBias * -1, "no_fp: frameSize == 0x28");
        CHECK(!model.hasFramePointer, "no_fp: no frame pointer");

        const StackSlot* s1 = model.slotAt(-8); // rsp+0x20 -> -8
        CHECK(s1 != nullptr, "no_fp: slot -8 present");
        if (s1) {
            CHECK(s1->promoted, "no_fp: slot -8 promoted");
            CHECK(s1->typeName == "uint32_t", "no_fp: slot -8 uint32_t");
        }
        const StackSlot* s2 = model.slotAt(-0x28); // rsp -> -0x28
        CHECK(s2 != nullptr, "no_fp: slot -0x28 present");
        if (s2) {
            CHECK(s2->promoted, "no_fp: slot -0x28 promoted");
            CHECK(s2->typeName == "uint32_t", "no_fp: slot -0x28 uint32_t");
            CHECK(s2->widths.count(4), "no_fp: slot -0x28 width 4");
            CHECK(!s2->addressTaken, "no_fp: slot -0x28 not address-taken");
            CHECK(!s2->overlaps, "no_fp: slot -0x28 not overlapping");
        }
    }

    // ---- parameters / return address: never promoted ----------------------
    {
        Image img;
        put(img, 0x1000, func_param());
        StackFrameModel model;
        CHECK(analyzeFunction(eng, img, 0x1000, arch, model),
              "param: analyze");
        const StackSlot* p = model.slotAt(8); // [rbp+0x10] -> 8
        CHECK(p != nullptr, "param: slot +8 present");
        if (p) {
            CHECK(p->role == StackSlotRole::PARAMETER,
                  "param: slot +8 is PARAMETER");
            CHECK(!p->promoted, "param: parameter slot never promoted");
        }
        const StackSlot* r = model.slotAt(0); // [rbp+0x8] -> 0
        CHECK(r != nullptr, "param: slot 0 present");
        if (r) {
            CHECK(r->role == StackSlotRole::RETURN_ADDRESS,
                  "param: slot 0 is RETURN_ADDRESS");
            CHECK(!r->promoted, "param: return-address slot never promoted");
        }
    }

    // ---- mixed width: fallback -------------------------------------------
    {
        Image img;
        put(img, 0x1000, func_mixed_width());
        StackFrameModel model;
        CHECK(analyzeFunction(eng, img, 0x1000, arch, model),
              "mixed: analyze");
        const StackSlot* s = model.slotAt(-0x18); // rbp-0x10 with bias -8
        CHECK(s != nullptr, "mixed: slot -0x18 present");
        if (s) {
            CHECK(s->widths.count(4) && s->widths.count(8),
                  "mixed: both widths recorded");
            CHECK(!s->promoted, "mixed: mixed-width slot not promoted");
        }
    }

    // ---- address taken: fallback ------------------------------------------
    {
        Image img;
        put(img, 0x1000, func_lea());
        StackFrameModel model;
        CHECK(analyzeFunction(eng, img, 0x1000, arch, model),
              "lea: analyze");
        const StackSlot* s = model.slotAt(-0x18); // rbp-0x10 with bias -8
        CHECK(s != nullptr, "lea: slot -0x18 present");
        if (s) {
            CHECK(s->addressTaken, "lea: slot address-taken");
            CHECK(!s->promoted, "lea: address-taken slot not promoted");
        }
    }

    if (failures == 0) std::printf("test_stack_recovery: all checks passed\n");
    else std::printf("test_stack_recovery: %d FAILURES\n", failures);
    return failures == 0 ? 0 : 1;
}
