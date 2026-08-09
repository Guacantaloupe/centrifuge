// ghra - a Ghidra reimplementation in C++17
// disasm_x86.cpp - hand-written x86 / x86-64 disassembler (pure C++, no deps)
//
// Coverage: the common legacy instruction set (integer + branch + SSE movs/
// arith + system instructions) with exact instruction lengths. VEX/EVEX and
// x87 are not decoded yet (decode returns false; linear sweep stops there).
// This is an interim decoder - the long-term plan is a Sleigh-style spec
// engine (see ROADMAP.md v0.3) that replaces hand-written tables.

#include "ghra/disasm.hpp"

#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>

namespace ghra {
namespace x86 {

namespace {

struct Dec {
    const uint8_t* c;
    size_t len;
    uint64_t addr;
    size_t pos = 0;
    bool is64;

    bool rex = false, rexw = false, rexr = false, rexx = false, rexb = false;
    bool pf66 = false, pf67 = false, pfF2 = false, pfF3 = false;

    std::string text;

    // 'v' operand size in bits (REX.W overrides 66)
    int opSize() const {
        if (rexw) return 64;
        if (pf66) return 16;
        return 32;
    }
    int addrSize() const { return (is64 && !pf67) ? 64 : 32; }
};

bool get8(Dec& d, uint8_t& v) {
    if (d.pos >= d.len) return false;
    v = d.c[d.pos++];
    return true;
}
bool get16(Dec& d, uint16_t& v) {
    if (d.pos + 2 > d.len) return false;
    v = static_cast<uint16_t>(d.c[d.pos] | (d.c[d.pos + 1] << 8));
    d.pos += 2;
    return true;
}
bool get32(Dec& d, uint32_t& v) {
    if (d.pos + 4 > d.len) return false;
    v = static_cast<uint32_t>(d.c[d.pos]) |
        (static_cast<uint32_t>(d.c[d.pos + 1]) << 8) |
        (static_cast<uint32_t>(d.c[d.pos + 2]) << 16) |
        (static_cast<uint32_t>(d.c[d.pos + 3]) << 24);
    d.pos += 4;
    return true;
}
bool get64(Dec& d, uint64_t& v) {
    uint32_t lo = 0, hi = 0;
    if (!get32(d, lo) || !get32(d, hi)) return false;
    v = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
    return true;
}

std::string hexOf(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}
// signed-aware immediate/offset formatting
std::string fmtI(int64_t v) {
    if (v < 0)
        return "-0x" + hexOf(static_cast<uint64_t>(-v)).substr(2);
    return hexOf(static_cast<uint64_t>(v));
}

const char* kCC[16] = {"o",  "no", "b",  "ae", "e",  "ne", "be", "a",
                       "s",  "ns", "p",  "np", "l",  "ge", "le", "g"};

std::string regName(int idx, int bits, bool rex, bool) {
    static const char* r8lo[] = {"al", "cl", "dl", "bl",
                                 "spl", "bpl", "sil", "dil"};
    static const char* r8hi[] = {"al", "cl", "dl", "bl",
                                 "ah", "ch", "dh", "bh"};
    static const char* r16[] = {"ax", "cx", "dx", "bx",
                                "sp", "bp", "si", "di"};
    static const char* r32[] = {"eax", "ecx", "edx", "ebx",
                                "esp", "ebp", "esi", "edi"};
    static const char* r64[] = {"rax", "rcx", "rdx", "rbx",
                                "rsp", "rbp", "rsi", "rdi"};
    const int i = idx & 7;
    if (bits == 128) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "xmm%d", idx);
        return buf;
    }
    if (idx >= 8) {
        char buf[8];
        if (bits == 8) std::snprintf(buf, sizeof(buf), "r%db", idx);
        else if (bits == 16) std::snprintf(buf, sizeof(buf), "r%dw", idx);
        else if (bits == 32) std::snprintf(buf, sizeof(buf), "r%dd", idx);
        else std::snprintf(buf, sizeof(buf), "r%d", idx);
        return buf;
    }
    switch (bits) {
    case 8: return (rex && i >= 4) ? r8lo[i] : r8hi[i];
    case 16: return r16[i];
    case 32: return r32[i];
    default: return r64[i];
    }
}

// Renders a memory operand for the current addressing mode. Consumes
// SIB/displacement bytes from the stream. Sets ripRel (64-bit mode only).
bool renderMem(Dec& d, uint8_t mod, uint8_t rm, int sizeBits, std::string& out,
               bool& ripRel, int64_t& ripDisp) {
    ripRel = false;
    ripDisp = 0;
    const bool ripBase = (d.addrSize() == 64);
    int base = -1, index = -1, scale = 0;
    int64_t disp = 0;

    if (rm == 4) { // SIB
        uint8_t sib;
        if (!get8(d, sib)) return false;
        scale = 1 << ((sib >> 6) & 3);
        const int idx = (sib >> 3) & 7;
        const int bs = sib & 7;
        if (idx != 4) index = idx | (d.rexx ? 8 : 0);
        if (!(bs == 5 && mod == 0)) base = bs | (d.rexb ? 8 : 0);
        if (mod == 1) {
            uint8_t v;
            if (!get8(d, v)) return false;
            disp = static_cast<int8_t>(v);
        } else if (mod == 2) {
            uint32_t v;
            if (!get32(d, v)) return false;
            disp = static_cast<int32_t>(v);
        } else if (bs == 5) {
            uint32_t v;
            if (!get32(d, v)) return false;
            disp = static_cast<int32_t>(v);
        }
    } else if (rm == 5 && mod == 0) {
        uint32_t v;
        if (!get32(d, v)) return false;
        disp = static_cast<int32_t>(v);
        if (ripBase) {
            ripRel = true;
            ripDisp = disp;
        }
    } else {
        base = rm | (d.rexb ? 8 : 0);
        if (mod == 1) {
            uint8_t v;
            if (!get8(d, v)) return false;
            disp = static_cast<int8_t>(v);
        } else if (mod == 2) {
            uint32_t v;
            if (!get32(d, v)) return false;
            disp = static_cast<int32_t>(v);
        }
    }

    std::string s = "[";
    bool any = false;
    if (ripRel) {
        // Ghidra-style absolute display: [0x...]
        s += hexOf(d.addr + d.pos + disp);
        any = true;
    } else {
        const int regBits = (d.addrSize() == 64) ? 64 : 32;
        if (base >= 0) {
            s += regName(base, regBits, d.rex, d.rexb);
            any = true;
        }
        if (index >= 0) {
            if (any) s += " + ";
            s += regName(index, regBits, d.rex, d.rexx);
            if (scale > 1) {
                char t[8];
                std::snprintf(t, sizeof(t), "*%d", scale);
                s += t;
            }
            any = true;
        }
        if (disp != 0 || !any) {
            if (any) {
                s += disp >= 0 ? " + " : " - ";
                s += hexOf(static_cast<uint64_t>(disp < 0 ? -disp : disp));
            } else {
                s += hexOf(static_cast<uint64_t>(disp));
            }
            any = true;
        }
    }
    s += "]";
    if (sizeBits == 8) out = "byte ptr " + s;
    else if (sizeBits == 16) out = "word ptr " + s;
    else if (sizeBits == 32) out = "dword ptr " + s;
    else if (sizeBits == 64) out = "qword ptr " + s;
    else if (sizeBits == 128) out = "oword ptr " + s;
    else out = s;
    return true;
}

struct ModRM {
    bool isReg = false;
    int regIdx = 0;      // reg field (+REX.R)
    std::string regStr;  // reg field rendered
    std::string rmStr;   // rm rendered (register or memory)
};

// Decodes a ModRM byte: renders the reg field and the rm operand.
bool decodeModRM(Dec& d, int rmBits, int regBits, ModRM& m) {
    uint8_t b;
    if (!get8(d, b)) return false;
    const int mod = (b >> 6) & 3, reg = (b >> 3) & 7, rm = b & 7;
    m.regIdx = reg | (d.rexr ? 8 : 0);
    m.regStr = regName(m.regIdx, regBits, d.rex, d.rexr);
    if (mod == 3) {
        m.isReg = true;
        m.rmStr = regName(rm | (d.rexb ? 8 : 0), rmBits, d.rex, d.rexb);
        return true;
    }
    bool ripRel = false;
    int64_t ripDisp = 0;
    return renderMem(d, mod, rm, rmBits, m.rmStr, ripRel, ripDisp);
}

void setText(Dec& d, const char* m, const std::string& a = "",
             const std::string& b = "", const std::string& c = "") {
    d.text = m;
    if (!a.empty()) {
        d.text += " ";
        d.text += a;
    }
    if (!b.empty()) {
        d.text += ", ";
        d.text += b;
    }
    if (!c.empty()) {
        d.text += ", ";
        d.text += c;
    }
}

} // namespace

// forward declarations (defined below, same namespace)
bool decodeTwoByte(Dec& d, Insn& out,
                   const std::function<void(Insn::Kind, uint64_t, bool)>& finish);
bool decodeGroup16(Dec& d, Insn& out,
                   const std::function<void(Insn::Kind, uint64_t, bool)>& finish);
bool decodeGroup15(Dec& d, Insn& out,
                   const std::function<void(Insn::Kind, uint64_t, bool)>& finish);
bool decodeThreeByte(Dec& d, Insn& out,
                     const std::function<void(Insn::Kind, uint64_t, bool)>& finish);

// ---------------------------------------------------------------------------
bool decodeOne(const uint8_t* code, size_t len, uint64_t addr, bool is64,
               Insn& out) {
    Dec d{code, len, addr, 0, is64};

    // ---- prefixes ----
    for (;;) {
        if (d.pos >= d.len) return false;
        const uint8_t b = d.c[d.pos];
        if (b == 0x66) {
            d.pf66 = true;
            d.pos++;
        } else if (b == 0x67) {
            d.pf67 = true;
            d.pos++;
        } else if (b == 0xF0) {
            d.pos++;
        } else if (b == 0xF2) {
            d.pfF2 = true;
            d.pos++;
        } else if (b == 0xF3) {
            d.pfF3 = true;
            d.pos++;
        } else if (is64 && (b & 0xF0) == 0x40) {
            d.rex = true;
            d.rexw = b & 8;
            d.rexr = b & 4;
            d.rexx = b & 2;
            d.rexb = b & 1;
            d.pos++;
        } else if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                   b == 0x64 || b == 0x65) {
            d.pos++; // segment override (ignored for display)
        } else {
            break;
        }
    }

    uint8_t op = 0;
    if (!get8(d, op)) return false;

    // ---- 32-bit-mode INC/DEC r32 (0x40-0x4F when no REX) ----
    if (!is64 && op >= 0x40 && op <= 0x4F) {
        const int r = op & 7;
        setText(d, (op & 8) ? "dec" : "inc", regName(r, 32, false, false));
        out.kind = Insn::OTHER;
        out.size = d.pos;
        out.text = d.text;
        return true;
    }

    auto finish = [&](Insn::Kind k, uint64_t target, bool known) {
        out.kind = k;
        out.target = target;
        out.targetKnown = known;
        out.size = d.pos;
        out.text = d.text;
    };

    // arithmetic/logic families 00-05/08-0D/.../38-3D share one shape
    if (op <= 0x3D && (op & 7) <= 5) {
        static const char* mn[] = {"add", "or", "adc", "sbb",
                                   "and", "sub", "xor", "cmp"};
        const int g = op >> 3; // 0..7
        const int f = op & 7;
        const char* m = mn[g];
        ModRM mr;
        switch (f) {
        case 0: // Eb, Gb
            if (!decodeModRM(d, 8, 8, mr)) return false;
            setText(d, m, mr.rmStr, mr.regStr);
            break;
        case 1: // Ev, Gv
            if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
            setText(d, m, mr.rmStr, mr.regStr);
            break;
        case 2: // Gb, Eb
            if (!decodeModRM(d, 8, 8, mr)) return false;
            setText(d, m, mr.regStr, mr.rmStr);
            break;
        case 3: // Gv, Ev
            if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
            setText(d, m, mr.regStr, mr.rmStr);
            break;
        case 4: { // AL, Ib
            uint8_t v;
            if (!get8(d, v)) return false;
            setText(d, m, "al", hexOf(v));
            break;
        }
        default: { // rAX, Iz
            const int sz = d.opSize();
            const std::string acc = regName(0, sz, false, false);
            if (sz == 16) {
                uint16_t v;
                if (!get16(d, v)) return false;
                setText(d, m, acc, hexOf(v));
            } else {
                uint32_t v;
                if (!get32(d, v)) return false;
                setText(d, m, acc, hexOf(v));
            }
            break;
        }
        }
        finish(Insn::OTHER, 0, false);
        return true;
    }

    switch (op) {
    case 0x06: case 0x0E: case 0x16: case 0x1E: { // PUSH seg (32-bit only)
        if (is64) return false;
        static const char* seg[] = {"es", "cs", "ss", "ds"};
        setText(d, "push", seg[(op >> 4) & 3]);
        break;
    }
    case 0x07: case 0x17: case 0x1F: { // POP seg (32-bit only)
        if (is64) return false;
        static const char* seg[] = {"es", "ss", "ds"};
        setText(d, "pop", seg[(op >> 4) & 3]);
        break;
    }
    case 0x27: case 0x2F: case 0x37: case 0x3F: { // DAA/DAS/AAA/AAS (32-bit)
        if (is64) return false;
        static const char* m[] = {"daa", "das", "aaa", "aas"};
        setText(d, m[(op >> 4) & 3]);
        break;
    }
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        setText(d, "push", regName(op & 7, 64, false, false));
        break;
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        setText(d, "pop", regName(op & 7, 64, false, false));
        break;
    case 0x63: { // MOVSXD (64-bit) / ARPL (32-bit)
        if (is64) {
            ModRM mr;
            if (!decodeModRM(d, 32, d.rexw ? 64 : 32, mr)) return false;
            setText(d, "movsxd", mr.regStr, mr.rmStr);
        } else {
            ModRM mr;
            if (!decodeModRM(d, 16, 16, mr)) return false;
            setText(d, "arpl", mr.rmStr, mr.regStr);
        }
        break;
    }
    case 0x68: { // PUSH Iz
        uint32_t v;
        if (!get32(d, v)) return false;
        setText(d, "push", hexOf(v));
        break;
    }
    case 0x69: { // IMUL Gv, Ev, Iz
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        uint32_t v;
        if (!get32(d, v)) return false;
        setText(d, "imul", mr.regStr, mr.rmStr, hexOf(v));
        break;
    }
    case 0x6A: { // PUSH Ib
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "push", fmtI(static_cast<int8_t>(v)));
        break;
    }
    case 0x6B: { // IMUL Gv, Ev, Ib
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "imul", mr.regStr, mr.rmStr, fmtI(static_cast<int8_t>(v)));
        break;
    }
    case 0x6C: setText(d, "insb"); break;
    case 0x6D: setText(d, d.opSize() == 16 ? "insw" : "insd"); break;
    case 0x6E: setText(d, "outsb"); break;
    case 0x6F: setText(d, d.opSize() == 16 ? "outsw" : "outsd"); break;

    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: { // Jcc Jb
        uint8_t v;
        if (!get8(d, v)) return false;
        const uint64_t t = addr + d.pos + static_cast<int8_t>(v);
        char m[16];
        std::snprintf(m, sizeof(m), "j%s", kCC[op & 0xF]);
        setText(d, m, hexOf(t));
        finish(Insn::JCC, t, true);
        return true;
    }

    case 0x80: case 0x82: { // group 1 Eb, Ib
        static const char* mn[] = {"add", "or", "adc", "sbb",
                                   "and", "sub", "xor", "cmp"};
        ModRM mr;
        if (!decodeModRM(d, 8, 0, mr)) return false;
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, mn[mr.regIdx & 7], mr.rmStr, hexOf(v));
        break;
    }
    case 0x81: { // group 1 Ev, Iz
        static const char* mn[] = {"add", "or", "adc", "sbb",
                                   "and", "sub", "xor", "cmp"};
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), 0, mr)) return false;
        std::string imm;
        if (d.opSize() == 16) {
            uint16_t v;
            if (!get16(d, v)) return false;
            imm = hexOf(v);
        } else {
            uint32_t v;
            if (!get32(d, v)) return false;
            imm = hexOf(v);
        }
        setText(d, mn[mr.regIdx & 7], mr.rmStr, imm);
        break;
    }
    case 0x83: { // group 1 Ev, Ib
        static const char* mn[] = {"add", "or", "adc", "sbb",
                                   "and", "sub", "xor", "cmp"};
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), 0, mr)) return false;
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, mn[mr.regIdx & 7], mr.rmStr, fmtI(static_cast<int8_t>(v)));
        break;
    }

    case 0x84: case 0x85: { // TEST
        ModRM mr;
        const int sz = (op == 0x84) ? 8 : d.opSize();
        if (!decodeModRM(d, sz, sz, mr)) return false;
        setText(d, "test", mr.rmStr, mr.regStr);
        break;
    }
    case 0x86: case 0x87: { // XCHG
        ModRM mr;
        const int sz = (op == 0x86) ? 8 : d.opSize();
        if (!decodeModRM(d, sz, sz, mr)) return false;
        setText(d, "xchg", mr.rmStr, mr.regStr);
        break;
    }
    case 0x88: case 0x89: { // MOV Eb/Ev, G
        ModRM mr;
        const int sz = (op == 0x88) ? 8 : d.opSize();
        if (!decodeModRM(d, sz, sz, mr)) return false;
        setText(d, "mov", mr.rmStr, mr.regStr);
        break;
    }
    case 0x8A: case 0x8B: { // MOV G, Eb/Ev
        ModRM mr;
        const int sz = (op == 0x8A) ? 8 : d.opSize();
        if (!decodeModRM(d, sz, sz, mr)) return false;
        setText(d, "mov", mr.regStr, mr.rmStr);
        break;
    }
    case 0x8C: { // MOV Ev, Sw
        ModRM mr;
        if (!decodeModRM(d, 16, 0, mr)) return false;
        if (mr.regIdx > 5) return false;
        static const char* seg[] = {"es", "cs", "ss", "ds", "fs", "gs"};
        setText(d, "mov", mr.rmStr, seg[mr.regIdx]);
        break;
    }
    case 0x8D: { // LEA Gv, M
        ModRM mr;
        if (!decodeModRM(d, 0, d.opSize(), mr)) return false;
        if (mr.isReg) return false; // LEA requires memory
        setText(d, "lea", mr.regStr, mr.rmStr);
        break;
    }
    case 0x8E: { // MOV Sw, Ev
        ModRM mr;
        if (!decodeModRM(d, 16, 0, mr)) return false;
        if (mr.regIdx > 5) return false;
        static const char* seg[] = {"es", "cs", "ss", "ds", "fs", "gs"};
        setText(d, "mov", seg[mr.regIdx], mr.rmStr);
        break;
    }
    case 0x8F: { // POP Ev
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), 0, mr)) return false;
        setText(d, "pop", mr.rmStr);
        break;
    }
    case 0x90:
        setText(d, d.pfF3 ? "pause" : "nop");
        break;
    case 0x91: case 0x92: case 0x93: case 0x94:
    case 0x95: case 0x96: case 0x97: // XCHG rAX, r
        setText(d, "xchg", regName(0, d.opSize(), false, false),
                regName(op & 7, d.opSize(), false, false));
        break;
    case 0x98:
        if (d.rexw) setText(d, "cdqe");
        else if (d.pf66) setText(d, "cbw");
        else setText(d, "cwde");
        break;
    case 0x99:
        if (d.rexw) setText(d, "cqo");
        else if (d.pf66) setText(d, "cwd");
        else setText(d, "cdq");
        break;
    case 0x9B: setText(d, "wait"); break;
    case 0x9C: setText(d, d.opSize() == 64 ? "pushfq" : "pushfd"); break;
    case 0x9D: setText(d, d.opSize() == 64 ? "popfq" : "popfd"); break;
    case 0x9E: setText(d, "sahf"); break;
    case 0x9F: setText(d, "lahf"); break;

    case 0xA0: case 0xA1: case 0xA2: case 0xA3: { // MOV moffs
        const bool toAcc = (op == 0xA0 || op == 0xA1);
        const bool byte = (op == 0xA0 || op == 0xA2);
        const int asz = d.addrSize();
        uint64_t moffs = 0;
        if (asz == 64) {
            if (!get64(d, moffs)) return false;
        } else if (asz == 32) {
            uint32_t v;
            if (!get32(d, v)) return false;
            moffs = v;
        } else {
            uint16_t v;
            if (!get16(d, v)) return false;
            moffs = v;
        }
        const std::string acc =
            byte ? "al" : regName(0, d.opSize(), false, false);
        const std::string mem =
            std::string(byte ? "byte ptr " : "") + "[" + hexOf(moffs) + "]";
        if (toAcc) setText(d, "mov", acc, mem);
        else setText(d, "mov", mem, acc);
        break;
    }
    case 0xA4: setText(d, "movsb"); break;
    case 0xA5:
        setText(d, d.opSize() == 64   ? "movsq"
                     : d.opSize() == 16 ? "movsw"
                                        : "movsd");
        break;
    case 0xA6: setText(d, "cmpsb"); break;
    case 0xA7:
        setText(d, d.opSize() == 64   ? "cmpsq"
                     : d.opSize() == 16 ? "cmpsw"
                                        : "cmpsd");
        break;
    case 0xA8: { // TEST AL, Ib
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "test", "al", hexOf(v));
        break;
    }
    case 0xA9: { // TEST rAX, Iz
        const int sz = d.opSize();
        if (sz == 16) {
            uint16_t v;
            if (!get16(d, v)) return false;
            setText(d, "test", regName(0, sz, false, false), hexOf(v));
        } else {
            uint32_t v;
            if (!get32(d, v)) return false;
            setText(d, "test", regName(0, sz, false, false), hexOf(v));
        }
        break;
    }
    case 0xAA: setText(d, "stosb"); break;
    case 0xAB:
        setText(d, d.opSize() == 64   ? "stosq"
                     : d.opSize() == 16 ? "stosw"
                                        : "stosd");
        break;
    case 0xAC: setText(d, "lodsb"); break;
    case 0xAD:
        setText(d, d.opSize() == 64   ? "lodsq"
                     : d.opSize() == 16 ? "lodsw"
                                        : "lodsd");
        break;
    case 0xAE: setText(d, "scasb"); break;
    case 0xAF:
        setText(d, d.opSize() == 64   ? "scasq"
                     : d.opSize() == 16 ? "scasw"
                                        : "scasd");
        break;

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7: { // MOV r8, Ib
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "mov", regName(op & 7, 8, d.rex, d.rexb), hexOf(v));
        break;
    }
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF: { // MOV r, Iz
        const int sz = d.opSize();
        std::string imm;
        if (sz == 64) {
            uint64_t v;
            if (!get64(d, v)) return false;
            imm = hexOf(v);
        } else if (sz == 16) {
            uint16_t v;
            if (!get16(d, v)) return false;
            imm = hexOf(v);
        } else {
            uint32_t v;
            if (!get32(d, v)) return false;
            imm = hexOf(v);
        }
        setText(d, "mov", regName(op & 7, sz, d.rex, d.rexb), imm);
        break;
    }

    case 0xC0: case 0xC1: { // group 2 Eb/Ev, Ib
        static const char* mn[] = {"rol", "ror", "rcl", "rcr",
                                   "shl", "shr", "sal", "sar"};
        ModRM mr;
        if (!decodeModRM(d, op == 0xC0 ? 8 : d.opSize(), 0, mr)) return false;
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, mn[mr.regIdx & 7], mr.rmStr, hexOf(v));
        break;
    }
    case 0xC2: { // RET Iw
        uint16_t v;
        if (!get16(d, v)) return false;
        setText(d, "ret", hexOf(v));
        finish(Insn::RET, 0, false);
        return true;
    }
    case 0xC3:
        setText(d, "ret");
        finish(Insn::RET, 0, false);
        return true;
    case 0xC6: { // MOV Eb, Ib (group 11)
        ModRM mr;
        if (!decodeModRM(d, 8, 0, mr)) return false;
        if ((mr.regIdx & 7) != 0) return false;
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "mov", mr.rmStr, hexOf(v));
        break;
    }
    case 0xC7: { // MOV Ev, Iz (group 11)
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), 0, mr)) return false;
        if ((mr.regIdx & 7) != 0) return false;
        std::string imm;
        if (d.opSize() == 16) {
            uint16_t v;
            if (!get16(d, v)) return false;
            imm = hexOf(v);
        } else {
            uint32_t v;
            if (!get32(d, v)) return false;
            imm = hexOf(v);
        }
        setText(d, "mov", mr.rmStr, imm);
        break;
    }
    case 0xC8: { // ENTER Iw, Ib
        uint16_t a;
        uint8_t b;
        if (!get16(d, a) || !get8(d, b)) return false;
        setText(d, "enter", hexOf(a), hexOf(b));
        break;
    }
    case 0xC9: setText(d, "leave"); break;
    case 0xCA: { // RETF Iw
        uint16_t v;
        if (!get16(d, v)) return false;
        setText(d, "retf", hexOf(v));
        finish(Insn::RET, 0, false);
        return true;
    }
    case 0xCB:
        setText(d, "retf");
        finish(Insn::RET, 0, false);
        return true;
    case 0xCC: setText(d, "int3"); break;
    case 0xCD: { // INT Ib
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "int", hexOf(v));
        break;
    }
    case 0xCF: setText(d, d.opSize() == 64 ? "iretq" : "iretd"); break;
    case 0xD0: case 0xD1: case 0xD2: case 0xD3: { // group 2 shifts
        static const char* mn[] = {"rol", "ror", "rcl", "rcr",
                                   "shl", "shr", "sal", "sar"};
        ModRM mr;
        const bool isByte = (op == 0xD0 || op == 0xD2);
        if (!decodeModRM(d, isByte ? 8 : d.opSize(), 0, mr)) return false;
        if (op == 0xD0 || op == 0xD1)
            setText(d, mn[mr.regIdx & 7], mr.rmStr, "1");
        else
            setText(d, mn[mr.regIdx & 7], mr.rmStr, "cl");
        break;
    }
    case 0xD7: setText(d, "xlatb"); break;

    case 0xE0: case 0xE1: case 0xE2: case 0xE3: { // LOOP* / JRCXZ
        uint8_t v;
        if (!get8(d, v)) return false;
        const uint64_t t = addr + d.pos + static_cast<int8_t>(v);
        const char* m = "loop";
        if (op == 0xE0) m = "loopne";
        else if (op == 0xE1) m = "loope";
        else if (op == 0xE3) m = d.pf67 ? "jecxz" : "jrcxz";
        setText(d, m, hexOf(t));
        finish(Insn::JCC, t, true);
        return true;
    }
    case 0xE4: { // IN AL, Ib
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "in", "al", hexOf(v));
        break;
    }
    case 0xE5: { // IN eAX, Ib
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "in", regName(0, d.opSize(), false, false), hexOf(v));
        break;
    }
    case 0xE6: { // OUT Ib, AL
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "out", hexOf(v), "al");
        break;
    }
    case 0xE7: { // OUT Ib, eAX
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, "out", hexOf(v), regName(0, d.opSize(), false, false));
        break;
    }
    case 0xE8: { // CALL rel32
        uint32_t rel;
        if (!get32(d, rel)) return false;
        const uint64_t t = addr + d.pos + static_cast<int32_t>(rel);
        setText(d, "call", hexOf(t));
        finish(Insn::CALL, t, true);
        return true;
    }
    case 0xE9: { // JMP rel32
        uint32_t rel;
        if (!get32(d, rel)) return false;
        const uint64_t t = addr + d.pos + static_cast<int32_t>(rel);
        setText(d, "jmp", hexOf(t));
        finish(Insn::JMP, t, true);
        return true;
    }
    case 0xEB: { // JMP rel8
        uint8_t rel;
        if (!get8(d, rel)) return false;
        const uint64_t t = addr + d.pos + static_cast<int8_t>(rel);
        setText(d, "jmp", hexOf(t));
        finish(Insn::JMP, t, true);
        return true;
    }
    case 0xEC: setText(d, "in", "al", "dx"); break;
    case 0xED: setText(d, "in", regName(0, d.opSize(), false, false), "dx"); break;
    case 0xEE: setText(d, "out", "dx", "al"); break;
    case 0xEF: setText(d, "out", "dx", regName(0, d.opSize(), false, false)); break;
    case 0xF1: setText(d, "int1"); break;
    case 0xF4: setText(d, "hlt"); break;
    case 0xF5: setText(d, "cmc"); break;
    case 0xF6: case 0xF7: { // group 3
        static const char* mn[] = {"test", "test", "not", "neg",
                                   "mul", "imul", "div", "idiv"};
        ModRM mr;
        const bool isByte = (op == 0xF6);
        if (!decodeModRM(d, isByte ? 8 : d.opSize(), 0, mr)) return false;
        const int g = mr.regIdx & 7;
        if (g == 0 || g == 1) {
            std::string imm;
            if (isByte) {
                uint8_t v;
                if (!get8(d, v)) return false;
                imm = hexOf(v);
            } else if (d.opSize() == 16) {
                uint16_t v;
                if (!get16(d, v)) return false;
                imm = hexOf(v);
            } else {
                uint32_t v;
                if (!get32(d, v)) return false;
                imm = hexOf(v);
            }
            setText(d, "test", mr.rmStr, imm);
        } else {
            setText(d, mn[g], mr.rmStr);
        }
        break;
    }
    case 0xF8: setText(d, "clc"); break;
    case 0xF9: setText(d, "stc"); break;
    case 0xFA: setText(d, "cli"); break;
    case 0xFB: setText(d, "sti"); break;
    case 0xFC: setText(d, "cld"); break;
    case 0xFD: setText(d, "std"); break;
    case 0xFE: { // group 4: INC/DEC Eb
        ModRM mr;
        if (!decodeModRM(d, 8, 0, mr)) return false;
        setText(d, (mr.regIdx & 7) == 0 ? "inc" : "dec", mr.rmStr);
        break;
    }
    case 0xFF: { // group 5
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), 0, mr)) return false;
        switch (mr.regIdx & 7) {
        case 0: setText(d, "inc", mr.rmStr); break;
        case 1: setText(d, "dec", mr.rmStr); break;
        case 2: setText(d, "call", mr.rmStr); finish(Insn::CALL, 0, false); return true;
        case 3: setText(d, "callf", mr.rmStr); finish(Insn::CALL, 0, false); return true;
        case 4: setText(d, "jmp", mr.rmStr); finish(Insn::JMP, 0, false); return true;
        case 5: setText(d, "jmpf", mr.rmStr); finish(Insn::JMP, 0, false); return true;
        case 6: setText(d, "push", mr.rmStr); break;
        default: return false;
        }
        break;
    }

    case 0x0F:
        return decodeTwoByte(d, out, finish);

    default:
        return false; // x87 D8-DF, VEX C4/C5, 60-62, 9A, EA, ...
    }

    finish(Insn::OTHER, 0, false);
    return true;
}

// ---------------------------------------------------------------------------
bool decodeTwoByte(Dec& d, Insn& out,
                   const std::function<void(Insn::Kind, uint64_t, bool)>& finish) {
    uint8_t op = 0;
    if (!get8(d, op)) return false;

    // SSE arithmetic 58-5F: base mnemonic + suffix by prefix
    if (op >= 0x58 && op <= 0x5F && op != 0x5B) {
        static const char* base[] = {"add", "mul", "cvt", "sub", "min",
                                     "div", "max", "sqrt"};
        const char* suffix = "ps";
        int sz = 128;
        if (d.pf66) {
            suffix = "pd";
        } else if (d.pfF3) {
            suffix = "ss";
            sz = 32;
        } else if (d.pfF2) {
            suffix = "sd";
            sz = 64;
        }
        ModRM mr;
        if (!decodeModRM(d, sz, 128, mr)) return false;
        char m[16];
        std::snprintf(m, sizeof(m), "%s%s", base[op - 0x58], suffix);
        setText(d, m, mr.regStr, mr.rmStr);
        finish(Insn::OTHER, 0, false);
        return true;
    }

    switch (op) {
    case 0x00: { // group 6: SLDT/STR/LLDT/LTR/VERR/VERW
        ModRM mr;
        if (!decodeModRM(d, 16, 0, mr)) return false;
        static const char* mn[] = {"sldt", "str", "lldt", "ltr",
                                   "verr", "verw", "", ""};
        if (!mn[mr.regIdx & 7][0]) return false;
        setText(d, mn[mr.regIdx & 7], mr.rmStr);
        break;
    }
    case 0x01:
        return decodeGroup16(d, out, finish);
    case 0x05: setText(d, "syscall"); break;
    case 0x06: setText(d, "clts"); break;
    case 0x07: setText(d, "sysret"); break;
    case 0x08: setText(d, "invd"); break;
    case 0x09: setText(d, "wbinvd"); break;
    case 0x0B: setText(d, "ud2"); break;
    case 0x10: case 0x11: { // MOVUPS/MOVSS/MOVSD
        const char* m = "movups";
        int sz = 128;
        if (d.pfF3) {
            m = "movss";
            sz = 32;
        } else if (d.pfF2) {
            m = "movsd";
            sz = 64;
        }
        ModRM mr;
        if (!decodeModRM(d, sz, 128, mr)) return false;
        if (op == 0x10) setText(d, m, mr.regStr, mr.rmStr);
        else setText(d, m, mr.rmStr, mr.regStr);
        break;
    }
    case 0x1F: { // NOP Ev (multi-byte nop)
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), 0, mr)) return false;
        setText(d, "nop");
        break;
    }
    case 0x20: case 0x21: case 0x22: case 0x23: { // MOV r64, CR/DR
        ModRM mr;
        if (!decodeModRM(d, 64, 0, mr)) return false;
        if (!mr.isReg) return false;
        const bool toSys = (op == 0x22 || op == 0x23);
        const char* kind = (op == 0x20 || op == 0x22) ? "cr" : "dr";
        char sys[8];
        std::snprintf(sys, sizeof(sys), "%s%d", kind, mr.regIdx & 15);
        if (toSys) setText(d, "mov", sys, mr.rmStr);
        else setText(d, "mov", mr.rmStr, sys);
        break;
    }
    case 0x28: case 0x29: { // MOVAPS/MOVAPD
        const char* m = d.pf66 ? "movapd" : "movaps";
        ModRM mr;
        if (!decodeModRM(d, 128, 128, mr)) return false;
        if (op == 0x28) setText(d, m, mr.regStr, mr.rmStr);
        else setText(d, m, mr.rmStr, mr.regStr);
        break;
    }
    case 0x30: setText(d, "wrmsr"); break;
    case 0x31: setText(d, "rdtsc"); break;
    case 0x32: setText(d, "rdmsr"); break;
    case 0x33: setText(d, "rdpmc"); break;
    case 0x34: setText(d, "sysenter"); break;
    case 0x35: setText(d, "sysexit"); break;
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F: { // CMOVcc
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        char m[16];
        std::snprintf(m, sizeof(m), "cmov%s", kCC[op & 0xF]);
        setText(d, m, mr.regStr, mr.rmStr);
        break;
    }
    case 0x57: { // XORPS/XORPD
        const char* m = d.pf66 ? "xorpd" : "xorps";
        ModRM mr;
        if (!decodeModRM(d, 128, 128, mr)) return false;
        setText(d, m, mr.regStr, mr.rmStr);
        break;
    }
    case 0x6E: case 0x7E: { // MOVD/MOVQ between GPR and XMM
        const bool toXmm = (op == 0x6E);
        const char* m = "movd";
        int gprSz = 32;
        if (d.rexw || d.pfF3) {
            m = "movq";
            gprSz = 64;
        }
        ModRM mr;
        if (!decodeModRM(d, gprSz, 128, mr)) return false;
        if (toXmm) setText(d, m, mr.regStr, mr.rmStr);
        else setText(d, m, mr.rmStr, mr.regStr);
        break;
    }
    case 0x6F: case 0x7F: { // MOVDQA/MOVDQU
        const char* m = d.pf66 ? "movdqa" : "movdqu";
        ModRM mr;
        if (!decodeModRM(d, 128, 128, mr)) return false;
        if (op == 0x6F) setText(d, m, mr.regStr, mr.rmStr);
        else setText(d, m, mr.rmStr, mr.regStr);
        break;
    }
    case 0x77: setText(d, "emms"); break;
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F: { // Jcc rel32
        uint32_t rel;
        if (!get32(d, rel)) return false;
        const uint64_t t = d.addr + d.pos + static_cast<int32_t>(rel);
        char m[16];
        std::snprintf(m, sizeof(m), "j%s", kCC[op & 0xF]);
        setText(d, m, hexOf(t));
        finish(Insn::JCC, t, true);
        return true;
    }
    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F: { // SETcc
        ModRM mr;
        if (!decodeModRM(d, 8, 0, mr)) return false;
        char m[16];
        std::snprintf(m, sizeof(m), "set%s", kCC[op & 0xF]);
        setText(d, m, mr.rmStr);
        break;
    }
    case 0xA0: setText(d, "push", "fs"); break;
    case 0xA1: setText(d, "pop", "fs"); break;
    case 0xA2: setText(d, "cpuid"); break;
    case 0xA3: { // BT Ev, Gv
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "bt", mr.rmStr, mr.regStr);
        break;
    }
    case 0xA4: case 0xA5: { // SHLD
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        if (op == 0xA4) {
            uint8_t v;
            if (!get8(d, v)) return false;
            setText(d, "shld", mr.rmStr, mr.regStr, hexOf(v));
        } else {
            setText(d, "shld", mr.rmStr, mr.regStr, "cl");
        }
        break;
    }
    case 0xA8: setText(d, "push", "gs"); break;
    case 0xA9: setText(d, "pop", "gs"); break;
    case 0xAB: { // BTS Ev, Gv
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "bts", mr.rmStr, mr.regStr);
        break;
    }
    case 0xAC: case 0xAD: { // SHRD
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        if (op == 0xAC) {
            uint8_t v;
            if (!get8(d, v)) return false;
            setText(d, "shrd", mr.rmStr, mr.regStr, hexOf(v));
        } else {
            setText(d, "shrd", mr.rmStr, mr.regStr, "cl");
        }
        break;
    }
    case 0xAF: { // IMUL Gv, Ev
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "imul", mr.regStr, mr.rmStr);
        break;
    }
    case 0xB0: case 0xB1: { // CMPXCHG
        ModRM mr;
        const int sz = (op == 0xB0) ? 8 : d.opSize();
        if (!decodeModRM(d, sz, sz, mr)) return false;
        setText(d, "cmpxchg", mr.rmStr, mr.regStr);
        break;
    }
    case 0xB2: { // LSS
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "lss", mr.regStr, mr.rmStr);
        break;
    }
    case 0xB3: { // BTR Ev, Gv
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "btr", mr.rmStr, mr.regStr);
        break;
    }
    case 0xB4: { // LFS
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "lfs", mr.regStr, mr.rmStr);
        break;
    }
    case 0xB5: { // LGS
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "lgs", mr.regStr, mr.rmStr);
        break;
    }
    case 0xB6: case 0xB7: { // MOVZX
        ModRM mr;
        const int srcBits = (op == 0xB6) ? 8 : 16;
        if (!decodeModRM(d, srcBits, d.opSize(), mr)) return false;
        setText(d, "movzx", mr.regStr, mr.rmStr);
        break;
    }
    case 0xB8: { // POPCNT (F3)
        if (!d.pfF3) return false;
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "popcnt", mr.regStr, mr.rmStr);
        break;
    }
    case 0xBA: { // group 8: BT/BTS/BTR/BTC Ev, Ib
        static const char* mn[] = {"", "", "", "", "bt", "bts", "btr", "btc"};
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), 0, mr)) return false;
        const int g = mr.regIdx & 7;
        if (!mn[g][0]) return false;
        uint8_t v;
        if (!get8(d, v)) return false;
        setText(d, mn[g], mr.rmStr, hexOf(v));
        break;
    }
    case 0xBB: { // BTC Ev, Gv
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "btc", mr.rmStr, mr.regStr);
        break;
    }
    case 0xBC: { // BSF
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "bsf", mr.regStr, mr.rmStr);
        break;
    }
    case 0xBD: { // BSR
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "bsr", mr.regStr, mr.rmStr);
        break;
    }
    case 0xBE: case 0xBF: { // MOVSX
        ModRM mr;
        const int srcBits = (op == 0xBE) ? 8 : 16;
        if (!decodeModRM(d, srcBits, d.opSize(), mr)) return false;
        setText(d, "movsx", mr.regStr, mr.rmStr);
        break;
    }
    case 0xC0: case 0xC1: { // XADD
        ModRM mr;
        const int sz = (op == 0xC0) ? 8 : d.opSize();
        if (!decodeModRM(d, sz, sz, mr)) return false;
        setText(d, "xadd", mr.rmStr, mr.regStr);
        break;
    }
    case 0xC3: { // MOVNTI
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        setText(d, "movnti", mr.rmStr, mr.regStr);
        break;
    }
    case 0xC7: { // group 9: CMPXCHG8B/16B, RDRAND, RDSEED
        ModRM mr;
        if (!decodeModRM(d, 64, 0, mr)) return false;
        switch (mr.regIdx & 7) {
        case 1:
            setText(d, d.rexw ? "cmpxchg16b" : "cmpxchg8b", mr.rmStr);
            break;
        case 6:
            setText(d, "rdrand", regName(0, d.opSize(), d.rex, false));
            break;
        case 7:
            setText(d, "rdseed", regName(0, d.opSize(), d.rex, false));
            break;
        default:
            return false;
        }
        break;
    }
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF: { // BSWAP
        setText(d, "bswap", regName(op & 7, d.opSize(), d.rex, false));
        break;
    }
    case 0xEF: { // PXOR (SSE2)
        if (!d.pf66) return false;
        ModRM mr;
        if (!decodeModRM(d, 128, 128, mr)) return false;
        setText(d, "pxor", mr.regStr, mr.rmStr);
        break;
    }
    case 0xAE:
        return decodeGroup15(d, out, finish);
    case 0x38:
        return decodeThreeByte(d, out, finish);
    default:
        return false;
    }

    finish(Insn::OTHER, 0, false);
    return true;
}

bool decodeGroup16(Dec& d, Insn& out,
                   const std::function<void(Insn::Kind, uint64_t, bool)>& finish) {
    uint8_t modrm = 0;
    if (!get8(d, modrm)) return false;
    const int mod = (modrm >> 6) & 3, reg = (modrm >> 3) & 7, rm = modrm & 7;
    if (mod == 3) return false; // XGETBV etc. - not decoded
    static const char* mn[] = {"sgdt", "sidt", "lgdt", "lidt",
                               "smsw", "lmsw", "invlpg", "invpcid"};
    if (reg > 7 || !mn[reg][0]) return false;
    std::string m;
    bool ripRel = false;
    int64_t ripDisp = 0;
    if (!renderMem(d, mod, rm, 0, m, ripRel, ripDisp)) return false;
    setText(d, mn[reg], m);
    finish(Insn::OTHER, 0, false);
    return true;
}

bool decodeGroup15(Dec& d, Insn& out,
                   const std::function<void(Insn::Kind, uint64_t, bool)>& finish) {
    uint8_t modrm = 0;
    if (!get8(d, modrm)) return false;
    const int mod = (modrm >> 6) & 3, reg = (modrm >> 3) & 7, rm = modrm & 7;
    if (mod == 3) {
        switch (reg) {
        case 5: setText(d, "lfence"); break;
        case 6: setText(d, "mfence"); break;
        case 7: setText(d, "sfence"); break;
        default: return false;
        }
        finish(Insn::OTHER, 0, false);
        return true;
    }
    static const char* mn[] = {"fxsave", "fxrstor", "ldmxcsr", "stmxcsr",
                               "xsave", "xrstor", "xsaveopt", "clflush"};
    if (reg > 7 || !mn[reg][0]) return false;
    std::string m;
    bool ripRel = false;
    int64_t ripDisp = 0;
    if (!renderMem(d, mod, rm, 0, m, ripRel, ripDisp)) return false;
    setText(d, mn[reg], m);
    finish(Insn::OTHER, 0, false);
    return true;
}

bool decodeThreeByte(Dec& d, Insn& out,
                     const std::function<void(Insn::Kind, uint64_t, bool)>& finish) {
    uint8_t op = 0;
    if (!get8(d, op)) return false;
    switch (op) {
    case 0xF0: case 0xF1: { // MOVBE
        ModRM mr;
        if (!decodeModRM(d, d.opSize(), d.opSize(), mr)) return false;
        if (op == 0xF0) setText(d, "movbe", mr.regStr, mr.rmStr);
        else setText(d, "movbe", mr.rmStr, mr.regStr);
        break;
    }
    case 0xF2: case 0xF3: { // CRC32
        ModRM mr;
        const int sz = (op == 0xF2) ? 8 : d.opSize();
        if (!decodeModRM(d, sz, 32, mr)) return false;
        setText(d, "crc32", mr.regStr, mr.rmStr);
        break;
    }
    default:
        return false;
    }
    finish(Insn::OTHER, 0, false);
    return true;
}

} // namespace x86
} // namespace ghra
