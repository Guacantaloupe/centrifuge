// ghra - a Ghidra reimplementation in C++17
// disasm.cpp - disassembler backends (100% C++, no external decoders)
#include "ghra/disasm.hpp"

#include <cstdio>
#include <string>

namespace ghra {

// implemented in disasm_x86.cpp / disasm_riscv.cpp
namespace x86 {
bool decodeOne(const uint8_t* code, size_t len, uint64_t addr, bool is64,
               Insn& out);
}
namespace riscv {
bool decodeOne(const uint8_t* code, size_t len, uint64_t addr, bool is64,
               Insn& out);
}

namespace {

class BuiltinDisassembler : public Disassembler {
public:
    BuiltinDisassembler(std::string arch, bool is64)
        : arch_(std::move(arch)), is64_(is64) {}

    bool disasmOne(const MemoryImage& mem, uint64_t addr, Insn& out) override {
        const size_t want = (arch_ == "x86-64" || arch_ == "x86") ? 16 : 8;
        uint8_t buf[16];
        size_t got = 0;
        for (size_t n : {want, size_t(8), size_t(4), size_t(2), size_t(1)}) {
            if (mem.read(addr, buf, n)) {
                got = n;
                break;
            }
        }
        if (got == 0) return false;
        bool ok = false;
        if (arch_ == "x86-64" || arch_ == "x86")
            ok = x86::decodeOne(buf, got, addr, arch_ == "x86-64", out);
        else
            ok = riscv::decodeOne(buf, got, addr, is64_, out);
        if (!ok) return false;
        // fill raw bytes for listing
        out.bytes.resize(out.size);
        if (out.size > got) out.size = got; // safety
        out.bytes.assign(buf, buf + out.size);
        return true;
    }

    std::string backendName() const override {
        return "builtin-c++ (" + arch_ + ")";
    }

private:
    std::string arch_;
    bool is64_;
};

// Fallback: lists raw bytes as pseudo-instructions. Used for architectures
// that don't have a decoder yet. Keeps the pipeline alive.
class RawDisassembler : public Disassembler {
public:
    explicit RawDisassembler(std::string arch) : arch_(std::move(arch)) {}
    bool disasmOne(const MemoryImage& mem, uint64_t addr, Insn& out) override {
        uint8_t b = 0;
        if (!mem.read(addr, &b, 1)) return false;
        char buf[32];
        std::snprintf(buf, sizeof(buf), ".byte 0x%02x", b);
        out.addr = addr;
        out.size = 1;
        out.bytes = {b};
        out.text = buf;
        out.kind = Insn::OTHER;
        return true;
    }
    std::string backendName() const override {
        return "raw (no decoder for " + arch_ + ")";
    }

private:
    std::string arch_;
};

} // namespace

std::unique_ptr<Disassembler> makeDisassembler(const std::string& arch) {
    if (arch == "x86-64") return std::make_unique<BuiltinDisassembler>(arch, true);
    if (arch == "x86") return std::make_unique<BuiltinDisassembler>(arch, false);
    if (arch == "riscv64") return std::make_unique<BuiltinDisassembler>(arch, true);
    if (arch == "riscv32") return std::make_unique<BuiltinDisassembler>(arch, false);
    return std::make_unique<RawDisassembler>(arch);
}

} // namespace ghra
