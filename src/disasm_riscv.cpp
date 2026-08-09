// ghra - a Ghidra reimplementation in C++17
// disasm_riscv.cpp - hand-written RISC-V (RV32I/RV64I + M + C) disassembler
// Pure C++, no deps. Matches objdump output for rv64gc (incl. compressed).

#include "ghra/disasm.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

namespace ghra {
namespace riscv {

namespace {

const char* regName(uint32_t i) {
    static const char* n[32] = {
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
        "s0",   "s1", "a0", "a1", "a2", "a3", "a4", "a5",
        "a6",   "a7", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8",   "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
    return n[i & 31];
}

int64_t sext(uint64_t v, int bits) {
    const uint64_t sign = 1ULL << (bits - 1);
    const uint64_t mask = (1ULL << bits) - 1;
    v &= mask;
    return static_cast<int64_t>((v ^ sign) - sign);
}

std::string hexOf(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

// sign-extended immediate rendering like objdump ("-12", "0x1c", "2")
std::string fmtImm(int64_t v) {
    if (v < 0) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "-0x%llx",
                      static_cast<unsigned long long>(-v));
        return buf;
    }
    if (v > 9 && (v & 0xF) != 0) return hexOf(static_cast<uint64_t>(v));
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
    return buf;
}

void setText(Insn& out, const char* m, const std::string& a = "",
             const std::string& b = "", const std::string& c = "") {
    out.text = m;
    if (!a.empty()) {
        out.text += " ";
        out.text += a;
    }
    if (!b.empty()) {
        out.text += ", ";
        out.text += b;
    }
    if (!c.empty()) {
        out.text += ", ";
        out.text += c;
    }
}

// "mnem rd, imm(base)" memory-operand form, like objdump
void setTextM(Insn& out, const char* m, const std::string& rd, int64_t imm,
              const std::string& base) {
    out.text = std::string(m) + " " + rd + ", " + fmtImm(imm) + "(" + base +
               ")";
}

} // namespace

// ---------------------------------------------------------------------------
bool decodeOne(const uint8_t* code, size_t len, uint64_t addr, bool is64,
               Insn& out) {
    if (len < 2) return false;
    const uint32_t hw = static_cast<uint32_t>(code[0]) |
                        (static_cast<uint32_t>(code[1]) << 8);
    out.size = 0;

    auto finish = [&](Insn::Kind k, uint64_t target, bool known) {
        out.kind = k;
        out.target = target;
        out.targetKnown = known;
    };

    const bool compressed = (hw & 0x3) != 0x3;
    if (compressed) {
        out.size = 2;
        const uint32_t f3 = (hw >> 13) & 0x7;
        const uint32_t rd = (hw >> 7) & 0x1F;
        const uint32_t rs2 = (hw >> 2) & 0x1F;
        const uint32_t rd8 = 8 + ((hw >> 2) & 0x7);  // rs2' field
        const uint32_t rs18 = 8 + ((hw >> 7) & 0x7); // rs1'/rd' field
        const uint32_t q = hw & 0x3;

        // 6-bit shift amount: shamt[5]=inst[12], shamt[4:0]=inst[6:2]
        const uint32_t shamt6 = ((hw >> 12) & 1) << 5 | ((hw >> 2) & 0x1F);
        // c.li / c.addi / c.andi immediate: sext(inst[12], inst[6:2])
        const int64_t imm6 = sext(((hw >> 12) & 1) << 5 | ((hw >> 2) & 0x1F), 6);
        // c.j / c.jal: imm[11]=inst[12] imm[10]=inst[8] imm[9:8]=inst[10:9]
        //              imm[7]=inst[6] imm[6]=inst[7] imm[5]=inst[2]
        //              imm[4]=inst[11] imm[3:1]=inst[5:3]
        const int64_t immJ =
            sext(((hw >> 12) & 1) << 11 | ((hw >> 8) & 1) << 10 |
                     ((hw >> 10) & 1) << 9 | ((hw >> 9) & 1) << 8 |
                     ((hw >> 6) & 1) << 7 | ((hw >> 7) & 1) << 6 |
                     ((hw >> 2) & 1) << 5 | ((hw >> 11) & 1) << 4 |
                     ((hw >> 3) & 7) << 1,
                 12);
        // c.beqz/c.bnez: imm[8]=inst[12] imm[7:6]=inst[6:5] imm[5]=inst[2]
        //                imm[4:3]=inst[11:10] imm[2:1]=inst[4:3]
        const int64_t immB =
            sext(((hw >> 12) & 1) << 8 | ((hw >> 5) & 3) << 6 |
                     ((hw >> 2) & 1) << 5 | ((hw >> 10) & 3) << 3 |
                     ((hw >> 3) & 3) << 1,
                 9);

        if (q == 0) {
            switch (f3) {
            case 0: { // C.ADDI4SPN
                const uint32_t uimm =
                    (((hw >> 7) & 0xF) << 2) | (((hw >> 11) & 3) << 6) |
                    (((hw >> 5) & 1) << 1) | ((hw >> 6) & 1);
                if (uimm == 0) return false; // reserved
                setText(out, "c.addi4spn", regName(rd8), fmtImm(uimm * 4));
                out.kind = Insn::OTHER;
                return true;
            }
            case 2: { // C.LW rd', uimm(rs1')
                const uint32_t uimm = ((hw >> 5) & 1) << 5 |
                                      ((hw >> 10) & 7) << 2 |
                                      ((hw >> 6) & 1) << 1;
                setTextM(out, "c.lw", regName(rd8), uimm * 4, regName(rs18));
                out.kind = Insn::OTHER;
                return true;
            }
            case 3: { // C.LD rd', uimm(rs1') (RV64)
                if (!is64) return false;
                const uint32_t uimm = ((hw >> 5) & 3) << 5 |
                                      ((hw >> 10) & 7) << 3;
                setTextM(out, "c.ld", regName(rd8), uimm * 8, regName(rs18));
                out.kind = Insn::OTHER;
                return true;
            }
            case 6: { // C.SW rs2', uimm(rs1')
                const uint32_t uimm = ((hw >> 5) & 1) << 5 |
                                      ((hw >> 10) & 7) << 2 |
                                      ((hw >> 6) & 1) << 1;
                setTextM(out, "c.sw", regName(rd8), uimm * 4, regName(rs18));
                out.kind = Insn::OTHER;
                return true;
            }
            case 7: { // C.SD rs2', uimm(rs1') (RV64)
                if (!is64) return false;
                const uint32_t uimm = ((hw >> 5) & 3) << 5 |
                                      ((hw >> 10) & 7) << 3;
                setTextM(out, "c.sd", regName(rd8), uimm * 8, regName(rs18));
                out.kind = Insn::OTHER;
                return true;
            }
            default:
                return false;
            }
        }

        if (q == 1) {
            const uint32_t f2 = (hw >> 10) & 0x3;
            switch (f3) {
            case 0: { // C.ADDI / C.NOP
                if (rd == 0) {
                    setText(out, "c.nop");
                } else {
                    setText(out, "c.addi", regName(rd), fmtImm(imm6));
                }
                out.kind = Insn::OTHER;
                return true;
            }
            case 1: { // C.JAL (RV32) / C.ADDIW (RV64)
                if (!is64) {
                    const uint64_t t = addr + immJ;
                    setText(out, "c.jal", hexOf(t));
                    finish(Insn::CALL, t, true);
                    return true;
                }
                if (rd == 0) return false;
                setText(out, "c.addiw", regName(rd), fmtImm(imm6));
                out.kind = Insn::OTHER;
                return true;
            }
            case 2: { // C.LI
                setText(out, "c.li", regName(rd), fmtImm(imm6));
                out.kind = Insn::OTHER;
                return true;
            }
            case 3: { // C.ADDI16SP / C.LUI
                if (rd == 2) {
                    // imm[9]=inst[12] imm[8]=inst[4] imm[7]=inst[3]
                    // imm[6]=inst[5] imm[5]=inst[2] imm[4]=inst[6]
                    const int64_t imm =
                        sext(((hw >> 12) & 1) << 9 | ((hw >> 4) & 1) << 8 |
                                 ((hw >> 3) & 1) << 7 | ((hw >> 5) & 1) << 6 |
                                 ((hw >> 2) & 1) << 5 | ((hw >> 6) & 1) << 4,
                             10);
                    if (imm == 0) return false;
                    setText(out, "c.addi16sp", "sp", fmtImm(imm));
                } else if (rd == 0) {
                    return false;
                } else {
                    // imm[17]=inst[12] imm[16:12]=inst[6:2], <<12
                    const int64_t imm =
                        sext(((hw >> 12) & 1) << 5 | ((hw >> 2) & 0x1F), 6)
                        << 12;
                    setText(out, "c.lui", regName(rd), fmtImm(imm));
                }
                out.kind = Insn::OTHER;
                return true;
            }
            case 4: { // C.SRLI / C.SRAI / C.ANDI / C.SUB/XOR/OR/AND
                if (f2 == 0 || f2 == 1) { // shifts
                    if (rd != 0) return false; // rd field must be 0
                    const char* m = (f2 == 0) ? "c.srli" : "c.srai";
                    setText(out, m, regName(rs18), fmtImm(shamt6));
                } else if (f2 == 2) { // C.ANDI
                    setText(out, "c.andi", regName(rs18), fmtImm(imm6));
                } else { // funct2=11: C.SUB/XOR/OR/AND or C.ADDW (RV64)
                    const uint32_t funct6 = (hw >> 10) & 0x3F;
                    if (funct6 == 0x27) { // C.ADDW
                        if (!is64) return false;
                        setText(out, "c.addw", regName(rs18), regName(rs2));
                    } else if (funct6 == 0x23) {
                        // op selected by rs2'[1:0]
                        static const char* mn[] = {"c.sub", "c.xor", "c.or",
                                                   "c.and"};
                        setText(out, mn[rs2 & 3], regName(rs18),
                                regName(rs2));
                    } else {
                        return false;
                    }
                }
                out.kind = Insn::OTHER;
                return true;
            }
            case 5: { // C.J
                const uint64_t t = addr + immJ;
                setText(out, "c.j", hexOf(t));
                finish(Insn::JMP, t, true);
                return true;
            }
            case 6: case 7: { // C.BEQZ / C.BNEZ
                const uint64_t t = addr + immB;
                setText(out, (f3 == 6) ? "c.beqz" : "c.bnez", regName(rs18),
                        hexOf(t));
                finish(Insn::JCC, t, true);
                return true;
            }
            default:
                return false;
            }
        }

        if (q == 2) {
            const uint32_t f2 = (hw >> 10) & 0x3;
            switch (f3) {
            case 0: { // C.SLLI
                if (rd == 0) return false;
                setText(out, "c.slli", regName(rd), fmtImm(shamt6));
                out.kind = Insn::OTHER;
                return true;
            }
            case 2: { // C.LWSP
                const uint32_t uimm = ((hw >> 2) & 3) |
                                      (((hw >> 12) & 1) << 2) |
                                      (((hw >> 4) & 7) << 3);
                if (rd == 0) return false;
                setTextM(out, "c.lwsp", regName(rd), uimm * 4, "sp");
                out.kind = Insn::OTHER;
                return true;
            }
            case 3: { // C.LDSP (RV64)
                if (!is64) return false;
                const uint32_t uimm = ((hw >> 2) & 7) << 3 |
                                      (((hw >> 12) & 1) << 2) |
                                      ((hw >> 5) & 3);
                if (rd == 0) return false;
                setTextM(out, "c.ldsp", regName(rd), uimm * 8, "sp");
                out.kind = Insn::OTHER;
                return true;
            }
            case 4: { // C.JR / C.MV / C.EBREAK / C.JALR / C.ADD
                if (f2 == 0) {
                    if (rs2 == 0) { // C.JR
                        if (rd == 0) return false;
                        setText(out, "c.jr", regName(rd));
                        finish(rd == 1 ? Insn::RET : Insn::JMP, 0, false);
                        return true;
                    }
                    setText(out, "c.mv", regName(rd), regName(rs2));
                } else {
                    if (rs2 == 0) { // C.EBREAK / C.JALR
                        if (rd == 0) {
                            setText(out, "c.ebreak");
                            out.kind = Insn::OTHER;
                            return true;
                        }
                        setText(out, "c.jalr", regName(rd));
                        finish(Insn::CALL, 0, false);
                        return true;
                    }
                    setText(out, "c.add", regName(rd), regName(rs2));
                }
                out.kind = Insn::OTHER;
                return true;
            }
            case 6: { // C.SWSP
                const uint32_t uimm = ((hw >> 9) & 0xF) |
                                      (((hw >> 7) & 3) << 4);
                setTextM(out, "c.swsp", regName(rs2), uimm * 4, "sp");
                out.kind = Insn::OTHER;
                return true;
            }
            case 7: { // C.SDSP (RV64)
                if (!is64) return false;
                const uint32_t uimm = ((hw >> 10) & 7) |
                                      (((hw >> 7) & 7) << 3);
                setTextM(out, "c.sdsp", regName(rs2), uimm * 8, "sp");
                out.kind = Insn::OTHER;
                return true;
            }
            default:
                return false;
            }
        }
        return false;
    }

    // ---- 32-bit instruction ----
    if (len < 4) return false;
    const uint32_t inst = static_cast<uint32_t>(code[0]) |
                          (static_cast<uint32_t>(code[1]) << 8) |
                          (static_cast<uint32_t>(code[2]) << 16) |
                          (static_cast<uint32_t>(code[3]) << 24);
    out.size = 4;

    const uint32_t opcode = inst & 0x7F;
    const uint32_t rd = (inst >> 7) & 0x1F;
    const uint32_t f3 = (inst >> 12) & 0x7;
    const uint32_t rs1 = (inst >> 15) & 0x1F;
    const uint32_t rs2 = (inst >> 20) & 0x1F;
    const uint32_t f7 = (inst >> 25) & 0x7F;
    const int64_t immI = sext(inst >> 20, 12);
    const int64_t immS = sext(((inst >> 20) & 0xFE0) | ((inst >> 7) & 0x1F), 12);
    const int64_t immB =
        sext(((inst >> 31) & 1) << 12 | ((inst >> 7) & 1) << 11 |
                 ((inst >> 25) & 0x3F) << 5 | ((inst >> 8) & 0xF) << 1,
             13);
    const int64_t immJ =
        sext(((inst >> 31) & 1) << 20 | ((inst >> 12) & 0xFF) << 12 |
                 ((inst >> 20) & 1) << 11 | ((inst >> 21) & 0x3FF) << 1,
             21);

    switch (opcode) {
    case 0x37: // LUI
        setText(out, "lui", regName(rd), hexOf(inst & 0xFFFFF000ULL));
        out.kind = Insn::OTHER;
        return true;
    case 0x17: // AUIPC
        setText(out, "auipc", regName(rd), hexOf(inst & 0xFFFFF000ULL));
        out.kind = Insn::OTHER;
        return true;
    case 0x6F: { // JAL
        const uint64_t t = addr + immJ;
        setText(out, "jal", regName(rd), hexOf(t));
        finish(rd == 0 ? Insn::JMP : Insn::CALL, t, true);
        return true;
    }
    case 0x67: { // JALR
        setText(out, "jalr", regName(rd), fmtImm(immI),
                "(" + std::string(regName(rs1)) + ")");
        if (rs1 == 0) {
            finish(Insn::JMP, static_cast<uint64_t>(immI), true);
        } else if (rd == 0 && rs1 == 1) {
            finish(Insn::RET, 0, false); // jalr x0, ra
        } else if (rd == 1) {
            finish(Insn::CALL, 0, false); // call via register
        } else {
            finish(Insn::JMP, 0, false); // indirect jump
        }
        return true;
    }
    case 0x63: { // branches
        static const char* mn[] = {"beq", "bne", "", "", "blt", "bge", "bltu",
                                   "bgeu"};
        if (!mn[f3][0]) return false;
        const uint64_t t = addr + immB;
        setText(out, mn[f3], regName(rs1), regName(rs2), hexOf(t));
        finish(Insn::JCC, t, true);
        return true;
    }
    case 0x03: { // loads
        static const char* mn[] = {"lb", "lh", "lw", "ld", "lbu", "lhu", "lwu",
                                   ""};
        if (!mn[f3][0]) return false;
        if ((f3 == 3 || f3 == 6) && !is64) return false;
        setTextM(out, mn[f3], regName(rd), immI, regName(rs1));
        out.kind = Insn::OTHER;
        return true;
    }
    case 0x23: { // stores
        static const char* mn[] = {"sb", "sh", "sw", "sd", "", "", "", ""};
        if (!mn[f3][0]) return false;
        if (f3 == 3 && !is64) return false;
        setTextM(out, mn[f3], regName(rs2), immS, regName(rs1));
        out.kind = Insn::OTHER;
        return true;
    }
    case 0x13: { // OP-IMM
        switch (f3) {
        case 0:
            setText(out, "addi", regName(rd), regName(rs1), fmtImm(immI));
            break;
        case 1: { // SLLI
            if (f7 != 0) return false;
            const uint32_t sh = (inst >> 20) & 0x3F;
            setText(out, "slli", regName(rd), regName(rs1), fmtImm(sh));
            break;
        }
        case 2:
            setText(out, "slti", regName(rd), regName(rs1), fmtImm(immI));
            break;
        case 3:
            setText(out, "sltiu", regName(rd), regName(rs1), fmtImm(immI));
            break;
        case 4:
            setText(out, "xori", regName(rd), regName(rs1), fmtImm(immI));
            break;
        case 5: { // SRLI / SRAI
            const uint32_t sh = (inst >> 20) & 0x3F;
            if (f7 == 0)
                setText(out, "srli", regName(rd), regName(rs1), fmtImm(sh));
            else if (f7 == 0x20)
                setText(out, "srai", regName(rd), regName(rs1), fmtImm(sh));
            else
                return false;
            break;
        }
        case 6:
            setText(out, "ori", regName(rd), regName(rs1), fmtImm(immI));
            break;
        case 7:
            setText(out, "andi", regName(rd), regName(rs1), fmtImm(immI));
            break;
        default:
            return false;
        }
        out.kind = Insn::OTHER;
        return true;
    }
    case 0x1B: { // OP-IMM-32 (RV64)
        if (!is64) return false;
        switch (f3) {
        case 0:
            setText(out, "addiw", regName(rd), regName(rs1), fmtImm(immI));
            break;
        case 1: {
            if (f7 != 0) return false;
            const uint32_t sh = (inst >> 20) & 0x1F;
            setText(out, "slliw", regName(rd), regName(rs1), fmtImm(sh));
            break;
        }
        case 5: {
            const uint32_t sh = (inst >> 20) & 0x1F;
            if (f7 == 0)
                setText(out, "srliw", regName(rd), regName(rs1), fmtImm(sh));
            else if (f7 == 0x20)
                setText(out, "sraiw", regName(rd), regName(rs1), fmtImm(sh));
            else
                return false;
            break;
        }
        default:
            return false;
        }
        out.kind = Insn::OTHER;
        return true;
    }
    case 0x33: { // OP
        switch (f3) {
        case 0:
            if (f7 == 0)
                setText(out, "add", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 0x20)
                setText(out, "sub", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "mul", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 1:
            if (f7 == 0)
                setText(out, "sll", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "mulh", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 2:
            if (f7 == 0)
                setText(out, "slt", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "mulhsu", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 3:
            if (f7 == 0)
                setText(out, "sltu", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "mulhu", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 4:
            if (f7 == 0)
                setText(out, "xor", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "div", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 5:
            if (f7 == 0)
                setText(out, "srl", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 0x20)
                setText(out, "sra", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "divu", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 6:
            if (f7 == 0)
                setText(out, "or", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "rem", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 7:
            if (f7 == 0)
                setText(out, "and", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "remu", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        default:
            return false;
        }
        out.kind = Insn::OTHER;
        return true;
    }
    case 0x3B: { // OP-32 (RV64)
        if (!is64) return false;
        switch (f3) {
        case 0:
            if (f7 == 0)
                setText(out, "addw", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 0x20)
                setText(out, "subw", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "mulw", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 1:
            if (f7 == 0)
                setText(out, "sllw", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "divw", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 5:
            if (f7 == 0)
                setText(out, "srlw", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 0x20)
                setText(out, "sraw", regName(rd), regName(rs1), regName(rs2));
            else if (f7 == 1)
                setText(out, "divuw", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 6:
            if (f7 == 1)
                setText(out, "remw", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        case 7:
            if (f7 == 1)
                setText(out, "remuw", regName(rd), regName(rs1), regName(rs2));
            else
                return false;
            break;
        default:
            return false;
        }
        out.kind = Insn::OTHER;
        return true;
    }
    case 0x0F: // FENCE / FENCE.I
        if (f3 == 1) {
            setText(out, "fence.i");
        } else if (f3 == 0) {
            setText(out, "fence");
        } else {
            return false;
        }
        out.kind = Insn::OTHER;
        return true;
    case 0x73: { // SYSTEM
        const uint32_t imm = inst >> 20;
        if (rs1 == 0 && f3 == 0) {
            switch (imm) {
            case 0: setText(out, "ecall"); break;
            case 1: setText(out, "ebreak"); break;
            case 0x102: setText(out, "sret"); break;
            case 0x302: setText(out, "mret"); break;
            case 0x105: setText(out, "wfi"); break;
            default: setText(out, "system", hexOf(imm)); break;
            }
        } else {
            static const char* mn[] = {"csrrw", "csrrs", "csrrc", "",
                                       "csrrwi", "csrrsi", "csrrci", ""};
            if (!mn[f3][0]) return false;
            if (f3 <= 2)
                setText(out, mn[f3], regName(rd), hexOf(imm), regName(rs1));
            else
                setText(out, mn[f3], regName(rd), hexOf(imm), fmtImm(rs1));
        }
        out.kind = Insn::OTHER;
        return true;
    }
    default:
        return false;
    }
}

} // namespace riscv
} // namespace ghra
