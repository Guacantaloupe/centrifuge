// ghra - a Ghidra reimplementation in C++17
// disasm.cpp - disassembler backends
#include "ghra/disasm.hpp"

#include <cstdio>
#include <cstring>
#include <utility>

#if defined(GHRA_HAVE_CAPSTONE)
#include <capstone/capstone.h>
#endif

namespace ghra {

#if defined(GHRA_HAVE_CAPSTONE)

class CapstoneDisassembler : public Disassembler {
public:
    CapstoneDisassembler(csh handle, cs_arch arch, std::string backendName)
        : handle_(handle), handleArch_(arch), backendName_(std::move(backendName)) {}
    ~CapstoneDisassembler() override { cs_close(&handle_); }

    bool disasmOne(const MemoryImage& mem, uint64_t addr, Insn& out) override {
        // Try progressively smaller reads so instructions near a block end
        // still decode (a truncated read just fails to decode).
        uint8_t buf[16];
        size_t got = 0;
        for (size_t want : {size_t(16), size_t(8), size_t(4), size_t(2), size_t(1)}) {
            if (mem.read(addr, buf, want)) {
                got = want;
                break;
            }
        }
        if (got == 0) return false;

        cs_insn* insn = nullptr;
        const size_t n = cs_disasm(handle_, buf, got, addr, 1, &insn);
        if (n == 0) return false;

        out.addr = addr;
        out.size = insn[0].size;
        out.bytes.assign(insn[0].bytes, insn[0].bytes + insn[0].size);
        out.text = std::string(insn[0].mnemonic);
        if (insn[0].op_str[0]) {
            out.text += " ";
            out.text += insn[0].op_str;
        }

        const char* m = insn[0].mnemonic;
        if (std::strcmp(m, "call") == 0) out.kind = Insn::CALL;
        else if (std::strncmp(m, "ret", 3) == 0) out.kind = Insn::RET;
        else if (std::strcmp(m, "jmp") == 0) out.kind = Insn::JMP;
        else if (m[0] == 'j' && m[1] != 'a' && m[1] != 'o') out.kind = Insn::JCC;
        else if (std::strcmp(m, "nop") == 0) out.kind = Insn::NOP;

        // Resolve branch/call targets from operand details.
        if (insn[0].detail) {
            const cs_detail* det = insn[0].detail;
            bool isBranch = false;
            for (uint8_t g = 0; g < det->groups_count; ++g) {
                if (det->groups[g] == CS_GRP_JUMP ||
                    det->groups[g] == CS_GRP_CALL ||
                    det->groups[g] == CS_GRP_BRANCH_RELATIVE) {
                    isBranch = true;
                    break;
                }
            }
            if (isBranch) {
                if (handleArch_ == CS_ARCH_X86) {
                    for (uint8_t i = 0; i < det->x86.op_count; ++i) {
                        const cs_x86_op& op = det->x86.operands[i];
                        if (op.type == X86_OP_IMM) {
                            out.target = static_cast<uint64_t>(op.imm);
                            out.targetKnown = true;
                        } else if (op.type == X86_OP_MEM &&
                                   op.mem.base == X86_REG_RIP) {
                            out.target = addr + insn[0].size +
                                         static_cast<uint64_t>(
                                             static_cast<int64_t>(op.mem.disp));
                            out.targetKnown = true;
                        }
                    }
                } else if (handleArch_ == CS_ARCH_ARM64) {
                    for (uint8_t i = 0; i < det->arm64.op_count; ++i) {
                        const cs_arm64_op& op = det->arm64.operands[i];
                        if (op.type == ARM64_OP_IMM) {
                            out.target = static_cast<uint64_t>(op.imm);
                            out.targetKnown = true;
                        }
                    }
                }
            }
        }
        cs_free(insn, 1);
        return true;
    }

    std::string backendName() const override { return backendName_; }

private:
    csh handle_;
    cs_arch handleArch_;
    std::string backendName_;
};

#endif // GHRA_HAVE_CAPSTONE

// Fallback: lists raw bytes as pseudo-instructions. Used when Capstone is
// unavailable or the architecture isn't supported. Keeps the pipeline alive
// so analysis/UI code can be developed without a full Sleigh port.
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
        return "raw (no capstone for " + arch_ + ")";
    }

private:
    std::string arch_;
};

std::unique_ptr<Disassembler> makeDisassembler(const std::string& arch) {
#if defined(GHRA_HAVE_CAPSTONE)
    cs_arch ca = CS_ARCH_MAX;
    cs_mode mode = CS_MODE_LITTLE_ENDIAN;
    if (arch == "x86-64") {
        ca = CS_ARCH_X86;
        mode = static_cast<cs_mode>(mode | CS_MODE_64);
    } else if (arch == "x86") {
        ca = CS_ARCH_X86;
        mode = static_cast<cs_mode>(mode | CS_MODE_32);
    } else if (arch == "aarch64") {
        ca = CS_ARCH_ARM64;
        mode = CS_MODE_ARM;
    } else if (arch == "arm") {
        ca = CS_ARCH_ARM;
        mode = CS_MODE_ARM;
    } else if (arch == "riscv64") {
        ca = CS_ARCH_RISCV;
        mode = static_cast<cs_mode>(mode | CS_MODE_RISCV64 | CS_MODE_RISCVC);
    } else if (arch == "riscv32") {
        ca = CS_ARCH_RISCV;
        mode = static_cast<cs_mode>(mode | CS_MODE_RISCV32 | CS_MODE_RISCVC);
    } else if (arch == "mips" || arch == "mips64") {
        ca = CS_ARCH_MIPS;
        mode = CS_MODE_MIPS32;
    } else if (arch == "ppc" || arch == "ppc64") {
        ca = CS_ARCH_PPC;
        mode = CS_MODE_64;
    }
    if (ca != CS_ARCH_MAX) {
        csh handle = 0;
        if (cs_open(ca, mode, &handle) == CS_ERR_OK) {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            std::string name = "capstone (" + arch + ")";
            return std::make_unique<CapstoneDisassembler>(handle, ca,
                                                          std::move(name));
        }
    }
#endif
    return std::make_unique<RawDisassembler>(arch);
}

} // namespace ghra
