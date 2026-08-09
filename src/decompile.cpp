// centrifuge - a Ghidra reimplementation in C++17
// decompile.cpp - minimal C decompiler (v0.4)
#include "centrifuge/decompile.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <sstream>

#include "centrifuge/cfg.hpp"

namespace centrifuge {

namespace {

constexpr uint64_t SP_OFF = 2 * 8;
constexpr uint64_t A0_OFF = 10 * 8;

// name for a stack slot relative to the frame (signed offset)
std::string localName(int64_t off) {
    if (off < 0) return "local_m" + std::to_string(-off);
    return "local_" + std::to_string(off);
}

// parse "sp - 272" / "sp + 272" / "sp" -> optional bias
bool parseSpExpr(const std::string& t, int64_t& bias) {
    std::string s = t;
    if (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
        int d = 0;
        bool full = true;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '(') d++;
            else if (s[i] == ')') {
                d--;
                if (d == 0 && i != s.size() - 1) { full = false; break; }
            }
        }
        if (full) s = s.substr(1, s.size() - 2);
    }
    if (s == "sp") {
        bias = 0;
        return true;
    }
    if (s.rfind("sp ", 0) != 0) return false;
    const char* p = s.c_str() + 3;
    char op = 0;
    while (*p == ' ') p++;
    if (*p == '+' || *p == '-') {
        op = *p;
        p++;
    } else {
        return false;
    }
    while (*p == ' ') p++;
    if (!*p) return false;
    const long long k = std::strtoll(p, nullptr, 10);
    bias = (op == '-') ? -k : k;
    return true;
}

const char* regName64(uint64_t offset) {
    static const char* n[32] = {
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
        "s0",   "s1", "a0", "a1", "a2", "a3", "a4", "a5",
        "a6",   "a7", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8",   "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
    const size_t i = offset / 8;
    return (i < 32) ? n[i] : "?";
}

std::string hexAddr(uint64_t a) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(a));
    return buf;
}

std::string fmtConst(uint64_t v, int size) {
    if (size <= 4)
        return std::to_string(static_cast<int32_t>(v));
    return std::to_string(static_cast<int64_t>(v));
}

const char* cCast(int size) {
    switch (size) {
    case 1: return "int8_t";
    case 2: return "int16_t";
    case 4: return "int32_t";
    default: return "int64_t";
    }
}
const char* uCast(int size) {
    switch (size) {
    case 1: return "uint8_t";
    case 2: return "uint16_t";
    case 4: return "uint32_t";
    default: return "uint64_t";
    }
}

struct CExpr {
    std::string text;
    int size = 8;
    bool isConst = false;
};

std::string stripParens(const std::string& s) {
    if (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
        int depth = 0;
        bool full = true;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '(') depth++;
            else if (s[i] == ')') {
                depth--;
                if (depth == 0 && i != s.size() - 1) { full = false; break; }
            }
        }
        if (full) return s.substr(1, s.size() - 2);
    }
    return s;
}

// parse "reg + K" / "reg - K" / "reg" / "K" (reg = [a-z][a-z0-9]*)
bool parseRegConstExpr(const std::string& t, std::string& reg, int64_t& k) {
    std::string s = stripParens(t);
    if (s.empty()) return false;
    // pure integer
    char* end = nullptr;
    const long long v = std::strtoll(s.c_str(), &end, 10);
    if (end && *end == 0) {
        reg.clear();
        k = v;
        return true;
    }
    // reg +- K
    const size_t sp = s.find(' ');
    if (sp == std::string::npos) return false;
    const std::string r = s.substr(0, sp);
    if (r.empty() || !std::isalpha(static_cast<unsigned char>(r[0])))
        return false;
    size_t p = sp;
    while (p < s.size() && s[p] == ' ') p++;
    if (p >= s.size() || (s[p] != '+' && s[p] != '-')) return false;
    const char op = s[p];
    p++;
    while (p < s.size() && s[p] == ' ') p++;
    if (p >= s.size()) return false;
    end = nullptr;
    const long long kk = std::strtoll(s.c_str() + p, &end, 10);
    if (!end || *end != 0) return false;
    reg = r;
    k = (op == '-') ? -kk : kk;
    return true;
}

// Per-block expression reconstruction. Registers are single C variables
// (their machine names); each assignment emits its expression text once and
// later expressions read the register's plain name - so register reuse and
// multi-predicate joins come out correct naturally (C sequential semantics
// match the machine).
class BlockEmitter {
public:
    std::ostringstream out;
    int indent = 1;
    std::string cond; // CBRANCH condition text ("" if none)
    bool hasCond = false;
    int64_t spBias = 0; // current sp offset relative to entry
    int64_t resolvedTarget = 0; // BRANCH target resolved via reg constants
    bool resolvedKnown = false;
    std::map<uint64_t, int64_t> regConst; // registers holding constants
    std::vector<std::pair<uint64_t, CExpr>> pending; // register writes

    // resolves a call target address to a function name ("" = indirect)
    std::function<std::string(uint64_t)> nameOf;

    explicit BlockEmitter(const CfgBlock& blk) : blk_(blk) {}

    // constant-fold a varnode through temps/registers to an integer
    bool resolveTarget(const PcodeInsn& pi, uint64_t id, int64_t& out) {
        const Varnode* v = pi.find(id);
        if (!v) return false;
        if (v->isConst()) {
            out = static_cast<int64_t>(v->offset);
            return true;
        }
        if (v->kind == Varnode::REGISTER) {
            auto it = regConst.find(v->offset);
            if (it == regConst.end()) return false;
            out = it->second;
            return true;
        }
        // UNIQUE temp: find its defining op
        for (const auto& op : pi.ops) {
            if (op.out != id) continue;
            if (op.op == POp::INT_ADD || op.op == POp::INT_SUB) {
                int64_t a = 0, b = 0;
                if (!resolveTarget(pi, op.in0, a)) return false;
                if (!resolveTarget(pi, op.in1, b)) return false;
                out = (op.op == POp::INT_SUB) ? a - b : a + b;
                return true;
            }
            if (op.op == POp::COPY) return resolveTarget(pi, op.in0, out);
            return false;
        }
        return false;
    }

    // emit "a0 = fname(args);" for a resolved call; returns true if emitted
    bool emitCall(const PcodeInsn& pi, uint64_t targetId) {
        if (!nameOf) return false;
        int64_t target = 0;
        if (!resolveTarget(pi, targetId, target)) return false;
        std::string fname = nameOf(static_cast<uint64_t>(target));
        if (fname.empty()) return false;
        std::string args;
        for (int i = 0; i < 8; ++i)
            args += (i ? ", " : "") + std::string(regName64((10 + i) * 8));
        pending.emplace_back(A0_OFF,
                             CExpr{fname + "(" + args + ")", 8, false});
        return true;
    }

    // returns the stack-slot offset if the address varnode is sp+const
    bool slotOf(const PcodeInsn& pi, uint64_t addrId, int64_t& off) const {
        const Varnode* v = pi.find(addrId);
        if (!v) return false;
        if (v->kind == Varnode::REGISTER && v->offset == SP_OFF) {
            off = spBias;
            return true;
        }
        if (v->kind != Varnode::UNIQUE) return false;
        // find the defining INT_ADD(sp, const)
        for (const auto& op : pi.ops) {
            if (op.out != addrId) continue;
            if (op.op != POp::INT_ADD && op.op != POp::INT_SUB) return false;
            const Varnode* a = pi.find(op.in0);
            const Varnode* b = pi.find(op.in1);
            const Varnode* spv = nullptr;
            const Varnode* cv = nullptr;
            if (a && a->kind == Varnode::REGISTER && a->offset == SP_OFF) {
                spv = a;
                cv = b;
            } else if (b && b->kind == Varnode::REGISTER &&
                       b->offset == SP_OFF) {
                spv = b;
                cv = a;
            }
            if (!spv || !cv || cv->kind != Varnode::CONST) return false;
            const int64_t k = static_cast<int64_t>(cv->offset);
            off = spBias + (op.op == POp::INT_SUB ? -k : k);
            return true;
        }
        return false;
    }

    void emit() {
        std::map<const Varnode*, CExpr> temps;
        hasCond = false;
        regConst.clear();
        pending.clear();

        auto exprOfV = [&](const Varnode* v) -> CExpr {
            if (!v) return CExpr{"0", 8, true};
            if (v->kind == Varnode::CONST)
                return CExpr{fmtConst(v->offset, v->size), v->size, true};
            if (v->kind == Varnode::REGISTER) {
                if (v->offset == 0) return CExpr{"0", v->size, true}; // zero
                return CExpr{regName64(v->offset), v->size, false};
            }
            auto it = temps.find(v);
            if (it != temps.end()) return it->second;
            return CExpr{"?", v->size, false};
        };

        for (const auto& pi : blk_.insns) {
            for (const auto& op : pi.ops) {
                if (op.op == POp::CBRANCH) {
                    cond = stripParens(exprOfV(pi.find(op.in1)).text);
                    hasCond = true;
                    continue;
                }
                if (op.op == POp::BRANCH) {
                    // resolve register-relative target (auipc+jalr pattern)
                    if (resolveTarget(pi, op.in0, resolvedTarget)) {
                        resolvedKnown = true;
                        const bool isCall = pi.text.rfind("jalr", 0) == 0 ||
                                            pi.text.rfind("call", 0) == 0;
                        if (isCall && emitCall(pi, op.in0))
                            resolvedKnown = false; // it's a call, not goto
                    }
                    continue;
                }
                if (op.op == POp::RETURN) continue;
                if (op.op == POp::CALL) {
                    if (!emitCall(pi, op.in0)) {
                        line("/* call " + exprOfV(pi.find(op.in0)).text +
                             " */");
                    }
                    continue;
                }
                const Varnode* vo = pi.find(op.out);
                if (!vo) {
                    if (op.op == POp::STORE) {
                        int64_t slot = 0;
                        const Varnode* vs = pi.find(op.in2);
                        if (slotOf(pi, op.in0, slot)) {
                            line(localName(slot) + " = " +
                                 stripParens(exprOfV(pi.find(op.in2)).text) +
                                 ";");
                        } else {
                            const CExpr a = exprOfV(pi.find(op.in0));
                            const CExpr v = exprOfV(pi.find(op.in2));
                            line("*((uint64_t *)(" + stripParens(a.text) +
                                 ")) = " + stripParens(v.text) + ";");
                        }
                        (void)vs;
                    }
                    continue;
                }
                CExpr r;
                switch (op.op) {
                case POp::COPY:
                    r = exprOfV(pi.find(op.in0));
                    break;
                case POp::INT_ADD:
                case POp::INT_SUB:
                case POp::INT_MULT:
                case POp::INT_AND:
                case POp::INT_OR:
                case POp::INT_XOR: {
                    CExpr a = exprOfV(pi.find(op.in0));
                    CExpr b = exprOfV(pi.find(op.in1));
                    const char* c = "?";
                    switch (op.op) {
                    case POp::INT_ADD: c = "+"; break;
                    case POp::INT_SUB: c = "-"; break;
                    case POp::INT_MULT: c = "*"; break;
                    case POp::INT_AND: c = "&"; break;
                    case POp::INT_OR: c = "|"; break;
                    case POp::INT_XOR: c = "^"; break;
                    default: break;
                    }
                    if (op.op == POp::INT_ADD && b.isConst) {
                        const int64_t n = static_cast<int64_t>(
                            std::strtoll(b.text.c_str(), nullptr, 10));
                        if (n < 0) {
                            c = "-";
                            b.text = std::to_string(-n);
                        }
                    }
                    if (a.isConst && a.text == "0") {
                        r = b;
                    } else if (b.isConst && b.text == "0") {
                        r = a;
                    } else if (a.isConst && b.isConst) {
                        const int64_t x = static_cast<int64_t>(
                            std::strtoll(a.text.c_str(), nullptr, 10));
                        const int64_t y = static_cast<int64_t>(
                            std::strtoll(b.text.c_str(), nullptr, 10));
                        int64_t z = 0;
                        switch (op.op) {
                        case POp::INT_ADD: z = x + y; break;
                        case POp::INT_SUB: z = x - y; break;
                        case POp::INT_MULT: z = x * y; break;
                        case POp::INT_AND: z = x & y; break;
                        case POp::INT_OR: z = x | y; break;
                        case POp::INT_XOR: z = x ^ y; break;
                        default: break;
                        }
                        r.text = std::to_string(z);
                        r.size = vo->size;
                        r.isConst = true;
                    } else {
                        r.text = "(" + a.text + " " + c + " " + b.text + ")";
                        r.size = vo->size;
                    }
                    break;
                }
                case POp::INT_LEFT:
                case POp::INT_RIGHT:
                case POp::INT_SRIGHT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    const char* c = op.op == POp::INT_LEFT ? "<<" : ">>";
                    r.text = "(" + a.text + " " + c + " " + b.text + ")";
                    r.size = vo->size;
                    break;
                }
                case POp::INT_EQUAL:
                case POp::INT_NOTEQUAL:
                case POp::INT_LESS:
                case POp::INT_SLESS:
                case POp::INT_LESSEQUAL:
                case POp::INT_SLESSEQUAL: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    const char* c = "?";
                    switch (op.op) {
                    case POp::INT_EQUAL: c = "=="; break;
                    case POp::INT_NOTEQUAL: c = "!="; break;
                    case POp::INT_LESS:
                    case POp::INT_SLESS: c = "<"; break;
                    case POp::INT_LESSEQUAL:
                    case POp::INT_SLESSEQUAL: c = "<="; break;
                    default: break;
                    }
                    r.text = "(" + a.text + " " + c + " " + b.text + ")";
                    r.size = 1;
                    break;
                }
                case POp::INT_ZEXT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const Varnode* vs = pi.find(op.in0);
                    r.text = "((int64_t)(" +
                             std::string(uCast(vs ? vs->size : 8)) + ")(" +
                             stripParens(a.text) + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::INT_SEXT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const Varnode* vs = pi.find(op.in0);
                    r.text = "((int64_t)(" +
                             std::string(cCast(vs ? vs->size : 8)) + ")(" +
                             stripParens(a.text) + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::SUBPIECE: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "((" + std::string(uCast(vo->size)) + ")(" +
                             stripParens(a.text) + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::INT_NEGATE: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "(~(" + stripParens(a.text) + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::BOOL_NEGATE: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "(!(" + stripParens(a.text) + "))";
                    r.size = 1;
                    break;
                }
                case POp::LOAD: {
                    int64_t slot = 0;
                    if (slotOf(pi, op.in0, slot)) {
                        r = CExpr{localName(slot), vo->size, false};
                    } else {
                        const CExpr a = exprOfV(pi.find(op.in0));
                        r.text = "(*(" + std::string(uCast(vo->size)) +
                                 " *)(" + stripParens(a.text) + "))";
                        r.size = vo->size;
                    }
                    break;
                }
                default:
                    r.text = "?";
                    r.size = vo->size;
                    break;
                }
                if (vo->kind == Varnode::REGISTER) {
                    if (vo->offset != 0) pending.emplace_back(vo->offset, r);
                } else {
                    temps[vo] = r;
                }
            }
            for (const auto& kv : pending) {
                // track sp adjustment (prologue/frame): sp = sp +/- K
                if (kv.first == SP_OFF) {
                    int64_t bias = 0;
                    if (parseSpExpr(kv.second.text, bias)) spBias += bias;
                }
                // track constant-valued registers (for jalr resolution)
                {
                    int64_t k = 0;
                    std::string reg;
                    if (parseRegConstExpr(kv.second.text, reg, k) &&
                        reg.empty())
                        regConst[kv.first] = k;
                    else
                        regConst.erase(kv.first);
                }
                line(std::string(regName64(kv.first)) + " = " +
                     stripParens(kv.second.text) + ";");
            }
            pending.clear();
        }
    }

    std::string retValue() const { return "a0"; }

private:
    const CfgBlock& blk_;
    void line(const std::string& s) {
        for (int i = 0; i < indent; ++i) out << "    ";
        out << s << "\n";
    }
};

} // namespace

std::string decompile(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end,
    const std::function<std::string(uint64_t)>& nameOf) {
    CfgBuilder cfg;
    if (!cfg.build(eng, read, start, end)) return "// failed to build CFG\n";

    std::ostringstream out;
    out << "// decompiled " << hexAddr(start) << "\n";

    std::set<uint64_t> labeled;
    for (const auto& b : cfg.blocks())
        if (b.start != start) labeled.insert(b.start); // all goto targets

    std::set<uint64_t> emitted;
    int64_t frameBias = 0; // sp bias right after the prologue (for locals)

    std::function<void(uint64_t, int)> emitBlock;
    emitBlock = [&](uint64_t a, int depth) {
        if (emitted.count(a)) {
            for (int i = 0; i < depth; ++i) out << "    ";
            out << "goto L" << hexAddr(a) << ";\n";
            return;
        }
        emitted.insert(a);
        const CfgBlock* b = cfg.blockAt(a);
        if (!b) return;
        if (labeled.count(a) && a != start) {
            for (int i = 0; i < depth; ++i) out << "    ";
            out << "L" << hexAddr(a) << ":\n";
        }
        BlockEmitter be(*b);
        be.indent = depth + 1;
        be.nameOf = nameOf;
        be.spBias = frameBias;
        be.emit();
        out << be.out.str(); // flush block body
        frameBias = std::min(frameBias, be.spBias); // keep prologue bias
        const PcodeInsn* term = b->terminator();
        if (!term) return;

        if (term->kind == Insn::RET) {
            for (int i = 0; i <= depth; ++i) out << "    ";
            out << "return " << be.retValue() << ";\n";
            return;
        }
        if (term->kind == Insn::JCC && term->targetKnown &&
            b->succs.size() == 2) {
            const uint64_t target = term->target;
            const uint64_t fall = b->succs[0];
            const CfgBlock* tb = cfg.blockAt(target);
            if (tb && tb->isRet() && cfg.predecessors(target).size() == 1) {
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "if (" << be.cond << ") {\n";
                BlockEmitter te(*tb);
                te.indent = depth + 2;
                te.nameOf = nameOf;
                te.spBias = frameBias;
                te.emit();
                out << te.out.str(); // flush if-body
                for (int i = 0; i <= depth + 1; ++i) out << "    ";
                out << "return " << te.retValue() << ";\n";
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "}\n";
                // do NOT propagate the if-body register state (it returns)
                emitBlock(fall, depth);
                return;
            }
            for (int i = 0; i <= depth; ++i) out << "    ";
            out << "if (" << be.cond << ") goto L" << hexAddr(target)
                << ";\n";
            emitBlock(fall, depth);
            return;
        }
        if (term->kind == Insn::JMP && term->targetKnown) {
            for (int i = 0; i <= depth; ++i) out << "    ";
            out << "goto L" << hexAddr(term->target) << ";\n";
            return;
        }
        if (be.resolvedKnown && (term->kind == Insn::JMP ||
                                 term->kind == Insn::OTHER)) {
            for (int i = 0; i <= depth; ++i) out << "    ";
            out << "goto L" << hexAddr(be.resolvedTarget) << ";\n";
            return;
        }
        if (!b->succs.empty()) emitBlock(b->succs[0], depth);
    };

    emitBlock(start, 0);
    // emit any blocks only reachable via branches (never on a fallthrough
    // path), so every label is defined
    for (const auto& b : cfg.blocks())
        if (!emitted.count(b.start)) emitBlock(b.start, 0);
    return out.str();
}

} // namespace centrifuge
