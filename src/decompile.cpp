// ghra - a Ghidra reimplementation in C++17
// decompile.cpp - minimal C decompiler (v0.4-lite)
#include "ghra/decompile.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <sstream>

#include "ghra/cfg.hpp"

namespace ghra {

namespace {

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

    explicit BlockEmitter(const CfgBlock& blk) : blk_(blk) {}

    void emit() {
        std::map<const Varnode*, CExpr> temps;
        std::vector<std::pair<uint64_t, CExpr>> pending; // reg writes
        hasCond = false;

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
                if (op.op == POp::BRANCH || op.op == POp::RETURN) continue;
                if (op.op == POp::CALL) {
                    line("/* call " + exprOfV(pi.find(op.in0)).text + " */");
                    continue;
                }
                const Varnode* vo = pi.find(op.out);
                if (!vo) {
                    if (op.op == POp::STORE) {
                        const CExpr a = exprOfV(pi.find(op.in0));
                        const CExpr v = exprOfV(pi.find(op.in2));
                        line("*((uint64_t *)(" + stripParens(a.text) +
                             ")) = " + stripParens(v.text) + ";");
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
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "(*(" + std::string(uCast(vo->size)) + " *)(" +
                             stripParens(a.text) + "))";
                    r.size = vo->size;
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
    uint64_t end) {
    CfgBuilder cfg;
    if (!cfg.build(eng, read, start, end)) return "// failed to build CFG\n";

    std::ostringstream out;
    out << "// decompiled " << hexAddr(start) << "\n";

    std::set<uint64_t> labeled;
    for (const auto& b : cfg.blocks())
        if (cfg.predecessors(b.start).size() > 1) labeled.insert(b.start);

    std::set<uint64_t> emitted;

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
        be.emit();
        out << be.out.str(); // flush block body
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
        if (!b->succs.empty()) emitBlock(b->succs[0], depth);
    };

    emitBlock(start, 0);
    return out.str();
}

} // namespace ghra
