// centrifuge - a Ghidra reimplementation in C++17
// decompile.cpp - minimal C decompiler (v0.4)
#include "centrifuge/decompile.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <map>
#include <regex>
#include <set>
#include <sstream>

#include "centrifuge/cfg.hpp"

namespace centrifuge {

namespace {

// name for a stack slot relative to the frame (signed offset)
std::string localName(int64_t off) {
    if (off < 0) return "local_m" + std::to_string(-off);
    return "local_" + std::to_string(off);
}

// parse "sp - 272" / "sp + 272" / "sp" -> optional bias
bool parseSpExpr(const std::string& t, const std::string& stackName,
                 int64_t& bias) {
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
    if (s == stackName) {
        bias = 0;
        return true;
    }
    const std::string prefix = stackName + " ";
    if (s.rfind(prefix, 0) != 0) return false;
    const char* p = s.c_str() + prefix.size();
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

std::string registerName(const std::string& architecture, uint64_t offset,
                         int size = 8) {
    if (architecture.rfind("riscv", 0) == 0) return regName64(offset);
    if (architecture.rfind("x86", 0) == 0) {
        if (size == 16) return "xmm" + std::to_string(offset / 8);
        if (size == 32) return "ymm" + std::to_string(offset / 8);
        if (size == 64) return "zmm" + std::to_string(offset / 8);
        if (offset >= 16384 && offset < 16384 + 8 * 8)
            return "mm" + std::to_string((offset - 16384) / 8);
        if (offset >= 8192 && offset < 8192 + 8 * 8)
            return "k" + std::to_string((offset - 8192) / 8);
        if (offset >= 24576 && offset < 24576 + 8 * 16)
            return "st" + std::to_string((offset - 24576) / 16);
        static const char* names[16] = {
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        };
        const size_t index = static_cast<size_t>(offset / 8);
        if (index < 16) return names[index];
        if (offset == X86_FS_BASE_OFFSET) return "fsbase";
        if (offset == X86_GS_BASE_OFFSET) return "gsbase";
        // Flag and system registers use byte-granular offsets.  Dividing the
        // offset by eight aliases CF/PF/AF/ZF/SF/OF to one C variable and
        // changes every conditional branch after a multi-flag instruction.
        return "r" + std::to_string(offset);
    }
    if (architecture == "aarch64" || architecture == "arm64")
        return "x" + std::to_string(offset / 8);
    return "r" + std::to_string(offset / 8);
}

bool x86GprSlice(const std::string& architecture, uint64_t offset, int size,
                 uint64_t& storageOffset, unsigned& shift) {
    if (architecture.rfind("x86", 0) != 0 || size <= 0 || size > 8 ||
        offset >= 16 * 8)
        return false;
    storageOffset = offset & ~uint64_t{7};
    const uint64_t byteOffset = offset - storageOffset;
    if (byteOffset + static_cast<uint64_t>(size) > 8) return false;
    shift = static_cast<unsigned>(byteOffset * 8);
    return true;
}

uint64_t registerStorageOffset(const std::string& architecture,
                               uint64_t offset, int size) {
    uint64_t storageOffset = offset;
    unsigned shift = 0;
    return x86GprSlice(architecture, offset, size, storageOffset, shift)
               ? storageOffset : offset;
}

namespace {
// Strip one fully-wrapping paren layer.  Local copy because the file-scope
// stripParens is defined later in the file.
std::string stripParensForward(const std::string& s) {
    if (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
        int depth = 0;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '(') depth++;
            else if (s[i] == ')') {
                depth--;
                if (depth == 0 && i != s.size() - 1) return s;
            }
        }
        if (depth == 0) return s.substr(1, s.size() - 2);
    }
    return s;
}
} // namespace

std::string x86RegisterWrite(const std::string& architecture, uint64_t offset,
                             int size, const std::string& expression) {
    uint64_t storageOffset = offset;
    unsigned shift = 0;
    if (!x86GprSlice(architecture, offset, size, storageOffset, shift))
        return registerName(architecture, offset, size) + " = " + expression;
    const std::string storage = registerName(architecture, storageOffset, 8);
    if (size == 8 && shift == 0) return storage + " = " + expression;
    // x86-64 writes to a 32-bit GPR zero the upper half.  Byte/word writes,
    // including AH/BH/CH/DH, preserve all bits outside their slice.
    if (size == 4 && shift == 0) {
        // A non-negative decimal constant within uint32 range needs no
        // zero-extension cast; "(uint32_t)(0)" is just "0".  Larger values
        // keep the cast: folded expressions are not pre-truncated to the
        // write width, so the cast is load-bearing for them.
        const std::string inner = stripParensForward(expression);
        bool inUint32Range = false;
        if (!inner.empty() &&
            std::all_of(inner.begin(), inner.end(),
                        [](char c) { return std::isdigit(static_cast<unsigned char>(c)); })) {
            const uint64_t value =
                std::strtoull(inner.c_str(), nullptr, 10);
            inUint32Range = value <= 0xffffffffULL;
        }
        return storage + " = " +
               (inUint32Range ? inner : "(uint32_t)(" + expression + ")");
    }
    const unsigned bits = static_cast<unsigned>(size * 8);
    const uint64_t valueMask = bits == 64
        ? std::numeric_limits<uint64_t>::max()
        : ((uint64_t{1} << bits) - 1);
    const uint64_t positionedMask = valueMask << shift;
    const uint64_t preserveMask = ~positionedMask;
    return storage + " = (" + storage + " & " +
           std::to_string(preserveMask) + "ULL) | (((uint64_t)(" +
           expression + ") & " + std::to_string(valueMask) + "ULL) << " +
           std::to_string(shift) + ")";
}

uint64_t stackPointerOffset(const std::string& architecture) {
    if (architecture.rfind("x86", 0) == 0) return 4 * 8;
    if (architecture == "aarch64" || architecture == "arm64") return 31 * 8;
    return 2 * 8;
}

// Phase 10f: a push/pop save slot confirmed by the function-level
// pre-analysis.  The store is emitted as savedName = reg and the matching
// rsp adjustment is folded away instead of simulating stack movement.
struct PushSlotInfo {
    std::string savedName;
    std::string storedReg;
    int64_t storeDelta = 0;
    int64_t loadDelta = 0;
};

// rsp delta of a single p-code op (sp op const / COPY of such a temp)
bool spWriteDelta(const PcodeInsn& pi, const PcodeOp& op,
                  const std::string& architecture, int64_t& delta) {
    const uint64_t spOffset = stackPointerOffset(architecture);
    auto constDelta = [&](const Varnode* a, const Varnode* b, POp opcode,
                          int64_t& out) {
        const Varnode* cv = nullptr;
        bool spFirst = false;
        if (a && a->kind == Varnode::REGISTER && a->offset == spOffset) {
            cv = b;
            spFirst = true;
        } else if (b && b->kind == Varnode::REGISTER &&
                   b->offset == spOffset) {
            cv = a;
        }
        if (!spFirst || !cv || cv->kind != Varnode::CONST) return false;
        out = (opcode == POp::INT_ADD) ? static_cast<int64_t>(cv->offset)
                                       : -static_cast<int64_t>(cv->offset);
        return true;
    };
    if (op.op == POp::INT_ADD || op.op == POp::INT_SUB)
        return constDelta(pi.find(op.in0), pi.find(op.in1), op.op, delta);
    if (op.op == POp::COPY) {
        const Varnode* in = pi.find(op.in0);
        if (!in) return false;
        if (in->kind == Varnode::CONST) {
            delta = static_cast<int64_t>(in->offset);
            return true;
        }
        if (in->kind == Varnode::UNIQUE) {
            for (const auto& op2 : pi.ops) {
                if (op2.out != in->id) continue;
                if (op2.op == POp::INT_ADD || op2.op == POp::INT_SUB)
                    return constDelta(pi.find(op2.in0), pi.find(op2.in1),
                                      op2.op, delta);
                return false;
            }
        }
    }
    return false;
}

// net constant rsp adjustment of an instruction, if every rsp write it
// performs is a constant adjustment (false when none or unparseable)
bool piRspDelta(const PcodeInsn& pi, const std::string& architecture,
                int64_t& delta) {
    const uint64_t spOffset = stackPointerOffset(architecture);
    int64_t net = 0;
    bool any = false;
    for (const auto& op : pi.ops) {
        const Varnode* vo = pi.find(op.out);
        if (!vo || vo->kind != Varnode::REGISTER) continue;
        if (registerStorageOffset(architecture, vo->offset, vo->size) !=
                spOffset ||
            vo->size != 8)
            continue;
        any = true;
        int64_t d = 0;
        if (!spWriteDelta(pi, op, architecture, d)) return false;
        net += d;
    }
    delta = net;
    return any;
}

// simulated rsp bias after executing a whole block
int64_t simulateBlockSp(const CfgBlock& b, int64_t startBias,
                        const std::string& architecture) {
    int64_t bias = startBias;
    for (const auto& pi : b.insns) {
        int64_t d = 0;
        if (piRspDelta(pi, architecture, d)) bias += d;
    }
    return bias;
}

// Phase 10f: re-base rsp references after folded push/pop adjustments.
// Every bare "rsp" identifier is rewritten to "(rsp - rebase)" so the text
// evaluates in the simulated frame (the output variable lags by rebase).
std::string rebaseRspText(const std::string& s, int64_t rebase) {
    if (rebase == 0 || s.find("rsp") == std::string::npos) return s;
    const std::string token = "rsp";
    const std::string replacement = "(rsp - " + std::to_string(rebase) + ")";
    std::string result;
    size_t at = 0;
    while (at < s.size()) {
        const size_t pos = s.find(token, at);
        if (pos == std::string::npos) {
            result += s.substr(at);
            break;
        }
        const bool left = pos == 0 ||
            !(std::isalnum(static_cast<unsigned char>(s[pos - 1])) ||
              s[pos - 1] == '_');
        const size_t after = pos + token.size();
        const bool right = after >= s.size() ||
            !(std::isalnum(static_cast<unsigned char>(s[after])) ||
              s[after] == '_');
        if (left && right)
            result += s.substr(at, pos - at) + replacement;
        else
            result += s.substr(at, pos - at + token.size());
        at = pos + token.size();
    }
    return result;
}


uint64_t framePointerOffset(const std::string& architecture) {
    if (architecture.rfind("x86", 0) == 0) return 5 * 8; // rbp
    return 8 * 8; // riscv s0 / arm64 x29 (unused by default)
}

uint64_t returnRegisterOffset(const std::string& architecture) {
    return architecture.rfind("riscv", 0) == 0 ? 10 * 8 : 0;
}

uint64_t secondaryReturnRegisterOffset(const std::string& architecture) {
    if (architecture.rfind("riscv", 0) == 0) return 11 * 8;
    if (architecture.rfind("x86", 0) == 0) return 2 * 8;
    return 8;
}

std::vector<uint64_t> defaultArgumentRegisters(const std::string& architecture) {
    if (architecture.rfind("x86", 0) == 0 &&
        architecture.find("win64") != std::string::npos)
        return {1 * 8, 2 * 8, 8 * 8, 9 * 8};
    if (architecture.rfind("x86", 0) == 0)
        return {7 * 8, 6 * 8, 2 * 8, 1 * 8, 8 * 8, 9 * 8};
    if (architecture == "aarch64" || architecture == "arm64")
        return {0, 8, 16, 24, 32, 40, 48, 56};
    std::vector<uint64_t> result;
    for (int i = 0; i < 8; ++i) result.push_back((10 + i) * 8);
    return result;
}

// Whole-identifier replacement (defined below; boundary-aware so renaming
// "a1" never touches "a11").
std::string replaceIdentifier(std::string text, const std::string& from,
                              const std::string& to);

// Strip one fully-wrapping paren layer (defined below).
std::string stripParens(const std::string& s);

// Readability: the ABI role of an 8-byte architectural register, for
// offsets that have one.  Argument registers are checked before the return
// register because they coincide on some ABIs (riscv a0) and the
// argument role is what a reader tracks at call sites.  Offsets without a
// role keep their architectural name (t0, s1, r10, ...).
std::string abiRoleName(const std::string& architecture, uint64_t offset) {
    if (offset == stackPointerOffset(architecture)) return "stack_ptr";
    if (offset == framePointerOffset(architecture)) return "frame_ptr";
    const auto arguments = defaultArgumentRegisters(architecture);
    for (size_t i = 0; i < arguments.size(); ++i)
        if (arguments[i] == offset)
            return "arg" + std::to_string(i);
    if (offset == returnRegisterOffset(architecture)) return "ret_val";
    return registerName(architecture, offset, 8);
}

// Whole-identifier rename of the ABI-role registers in emitted C text.
// replaceIdentifier is boundary-aware, so renaming "a1" never touches
// "a11" or "local_a1".  Applied to complete function bodies (and the
// typed wrapper re-applies it to its declarations), so every reference
// and every declaration stays in sync.
std::string renameAbiRoles(std::string text, const std::string& architecture) {
    const int registerCount =
        architecture.rfind("x86", 0) == 0 ? 16 : 32;
    for (int index = 0; index < registerCount; ++index) {
        const uint64_t offset = static_cast<uint64_t>(index) * 8;
        const std::string from = registerName(architecture, offset, 8);
        const std::string to = abiRoleName(architecture, offset);
        if (from != to) text = replaceIdentifier(text, from, to);
    }
    return text;
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
    case 16: return "RecoveredVector128";
    case 32: return "RecoveredVector256";
    case 64: return "RecoveredVector512";
    default: return "uint64_t";
    }
}

struct CExpr {
    std::string text;
    int size = 8;
    bool isConst = false;
    bool floating = false;
    // C type of the emitted text when known (e.g. "uint64_t", "int32_t").
    // Empty means unknown; castTo() only elides a conversion when the
    // inner expression already carries exactly the target type, so
    // propagation is conservative and never changes semantics.
    std::string ctype;
    // Architectural registers read while forming this expression.  Keeping
    // both the storage offset and the textual register view lets the emitter
    // preserve instruction-level parallel writes (for example RDX:RAX from
    // one-operand MUL/IMUL) without confusing RAX with EAX.
    std::map<uint64_t, std::set<std::string>> registerRefs;
    // A load cannot safely be re-evaluated after an intervening store/call.
    bool readsMemory = false;
};

std::string replaceIdentifier(std::string text, const std::string& from,
                              const std::string& to) {
    if (from.empty()) return text;
    const auto isIdentifier = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
    };
    size_t position = 0;
    while ((position = text.find(from, position)) != std::string::npos) {
        const bool leftBoundary = position == 0 ||
            !isIdentifier(text[position - 1]);
        const size_t end = position + from.size();
        const bool rightBoundary = end == text.size() ||
            !isIdentifier(text[end]);
        if (leftBoundary && rightBoundary) {
            text.replace(position, from.size(), to);
            position += to.size();
        } else {
            position += from.size();
        }
    }
    return text;
}

std::string safeIdentifier(std::string text) {
    for (char& c : text)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') c = '_';
    return text;
}

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

// Byte width of a fixed-width integer type name (e.g. "uint32_t" -> 4);
// 0 for anything else (floats, unknown names).
int typeWidth(const std::string& type) {
    if (type == "int8_t" || type == "uint8_t") return 1;
    if (type == "int16_t" || type == "uint16_t") return 2;
    if (type == "int32_t" || type == "uint32_t") return 4;
    if (type == "int64_t" || type == "uint64_t") return 8;
    return 0;
}

// If `inner` starts with "(T)(...)" where T is a fixed-width integer type,
// return true and set `type`/`rest` to T and the remaining "(...)" text.
bool matchLeadingCast(const std::string& inner, std::string& type,
                      std::string& rest) {
    if (inner.size() < 2 || inner.front() != '(') return false;
    const size_t close = inner.find(")(", 1);
    if (close == std::string::npos) return false;
    const std::string candidate = inner.substr(1, close - 1);
    if (typeWidth(candidate) == 0) return false;
    if (!std::all_of(candidate.begin(), candidate.end(),
                     [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }))
        return false;
    const std::string remainder = inner.substr(close + 1); // includes trailing ')'
    if (remainder.empty() || remainder.back() != ')') return false;
    // The operand must be one fully-wrapped "(...)" group - otherwise the
    // cast only covers a prefix (e.g. "(uint32_t)(x) + (uint32_t)(y)")
    // and treating the remainder as the operand would corrupt the text.
    if (remainder.front() != '(') return false;
    int depth = 0;
    bool fullyWrapped = true;
    for (size_t i = 0; i < remainder.size(); ++i) {
        if (remainder[i] == '(') depth++;
        else if (remainder[i] == ')') {
            depth--;
            if (depth == 0 && i != remainder.size() - 1) {
                fullyWrapped = false;
                break;
            }
        }
    }
    if (!fullyWrapped || depth != 0) return false;
    type = candidate;
    rest = remainder;
    return true;
}

// Does `inner` consist of exactly "(target)(...)" with the conversion's
// closing paren at the final character?
bool startsWithCast(const std::string& inner, const std::string& target) {
    const std::string prefix = "(" + target + ")(";
    if (inner.rfind(prefix, 0) != 0) return false;
    int depth = 1; // inside the second '(' of the prefix
    for (size_t i = prefix.size(); i < inner.size(); ++i) {
        if (inner[i] == '(') depth++;
        else if (inner[i] == ')') {
            depth--;
            if (depth == 0) return i == inner.size() - 1;
        }
    }
    return false;
}

// Wrap `e` in a conversion to `target`, eliding conversions that carry no
// additional information:
//   - the expression already carries the target type (metadata or
//     textually), or
//   - it begins with a same-width conversion: for two's-complement targets
//     "(int32_t)((uint32_t)x)" and "(uint32_t)((int32_t)x)" both reduce to
//     the low bits of x, so the inner conversion can be replaced by the
//     target one. Semantics are unchanged on the platforms this project
//     targets (the emitter already relies on two's-complement conversions
//     for SUBPIECE and width-polymorphic arithmetic).
std::string castTo(const CExpr& e, const std::string& target) {
    const std::string inner = stripParens(e.text);
    if (e.ctype == target) return inner;
    if (startsWithCast(inner, target)) return inner;
    std::string leading, rest;
    if (matchLeadingCast(inner, leading, rest) &&
        typeWidth(leading) == typeWidth(target))
        return "(" + target + ")(" + stripParens(rest) + ")";
    return "(" + target + ")(" + inner + ")";
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
// Phase 10b-2: an argument-setup expression may be inlined into a call site
// only when evaluating it again has no side effects or deferred memory reads.
// Constants and register arithmetic qualify; anything with a function-like call
// (identifier directly before '(') is kept as a register variable to avoid
// duplicate evaluation.
bool inlineableExpression(const CExpr& expression) {
    if (expression.readsMemory) return false;
    if (expression.text.empty()) return false;
    if (expression.isConst) return true;
    size_t pos = 0;
    while ((pos = expression.text.find('(', pos)) != std::string::npos) {
        if (pos > 0) {
            const char previous = expression.text[pos - 1];
            if (std::isalnum(static_cast<unsigned char>(previous)) ||
                previous == '_' || previous == '>')
                return false;
        }
        ++pos;
    }
    return true;
}

// Phase 10e: register references reachable from a varnode (through temps).
void collectRegRefs(const PcodeInsn& pi, uint64_t id,
                    const std::string& architecture,
                    std::set<uint64_t>& out, int depth = 0) {
    if (depth > 6) return;
    const Varnode* v = pi.find(id);
    if (!v) return;
    if (v->kind == Varnode::REGISTER) {
        out.insert(registerStorageOffset(architecture, v->offset, v->size));
        return;
    }
    if (v->kind != Varnode::UNIQUE) return;
    for (const auto& op : pi.ops) {
        if (op.out != id) continue;
        collectRegRefs(pi, op.in0, architecture, out, depth + 1);
        collectRegRefs(pi, op.in1, architecture, out, depth + 1);
        collectRegRefs(pi, op.in2, architecture, out, depth + 1);
        return;
    }
}

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
    // Phase 10b-2: block-local register definitions (storage -> defining
    // expression).  Used to inline argument setup into call sites
    // (rcx = X; FUN(rcx) -> FUN(X)); entries are invalidated when a
    // dependency is redefined or at block boundaries.
    std::map<uint64_t, CExpr> regExpr;

    // resolves a call target address to a function name ("" = indirect)
    std::function<std::string(uint64_t)> nameOf;
    std::function<std::optional<FunctionSignature>(uint64_t)> signatureOf;
    // True for data-segment slots whose value is a `jmp rax` trampoline
    // (MSVC /guard:cf __guard_dispatch_icall_fptr).  The machine does
    // mov rax, <real target>; call [slot]; the trampoline jumps to rax.
    // Recovered calls to such slots must forward the rax expression as
    // the first argument (the stub treats a0 as the call target).
    std::function<bool(uint64_t)> guardSlotOf;
    std::string architecture = "riscv64";
    bool useRecoveredRuntime = false;
    const StackFrameModel* stackModel = nullptr; // Native Source Backend
    const GlobalObjectRecovery* globals = nullptr; // Phase 8
    // Phase 10a: in the entry block, ABI argument registers read before
    // any redefinition are named param1..N instead of their machine names
    // (local_m76 = (uint32_t)(rcx) becomes (uint32_t)(param1)).
    bool entryBlock = false;
    std::map<uint64_t, int> paramIndex; // ABI reg storage -> param number
    std::set<uint64_t> paramDefined;    // ABI regs redefined in entry block
    // Phase 10g: x86 flag registers (r4096..r4101) actually read anywhere
    // in the function (branch conditions, adc/sbb, cmov) survive; dead flag
    // writes are dropped from the output.
    const std::set<uint64_t>* liveFlags = nullptr;
    // Phase 10f: push/pop save slots (native view).  A slot confirmed by the
    // function-level pre-analysis is emitted as a plain saved_<slot> variable
    // instead of a simulated rsp adjustment + local_m<slot> slot: the paired
    // rsp write is folded away and later rsp-relative flag expressions are
    // re-based through rspRebase so the C stays semantically identical.
    const std::map<int64_t, PushSlotInfo>* pushSlots = nullptr;
    bool dropRspWrite = false; // this instruction's rsp write is folded
    int64_t rspRebase = 0;     // output rsp = simulated rsp + rspRebase
    // Phase 10e: liveOut[b] = registers read in any successor without an
    // intervening write; a side-effect-free write to a non-live, non-return
    // register that is also not read later in this block (blockReadPos) is
    // dead and its line is dropped.  liveOutCall additionally carries ABI
    // call-argument registers (which only block elimination of non-constant
    // definitions, since 10b-2 always inlines constant argument setups).
    const std::set<uint64_t>* liveOut = nullptr;
    const std::set<uint64_t>* liveOutCall = nullptr;
    const std::set<uint64_t>* callArgsLocal = nullptr;
    const std::map<uint64_t, std::vector<int>>* readPos = nullptr;
    // Phase 10h: memory access for string-literal recovery at call sites.
    std::function<bool(uint64_t, void*, size_t)> memRead;

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
            const uint64_t storage =
                registerStorageOffset(architecture, v->offset, v->size);
            auto it = regConst.find(storage);
            if (it == regConst.end()) return false;
            out = it->second;
            uint64_t base = v->offset;
            unsigned shift = 0;
            if (x86GprSlice(architecture, v->offset, v->size, base, shift) &&
                (v->size < 8 || shift)) {
                const unsigned bits = static_cast<unsigned>(v->size * 8);
                const uint64_t mask = bits == 64
                    ? std::numeric_limits<uint64_t>::max()
                    : ((uint64_t{1} << bits) - 1);
                out = static_cast<int64_t>(
                    (static_cast<uint64_t>(out) >> shift) & mask);
            }
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
        const bool guardSlot = guardSlotOf && guardSlotOf(static_cast<uint64_t>(target));
        if (guardSlot) {
            // Forward the pointer the machine loaded into rax as the
            // call target (a0 of the stub).  The remaining ABI arguments
            // shift to a1..a7.  rax's defining expression lives in
            // regExpr; if unavailable, fall back to the register name so
            // the emitted call still compiles.
            const uint64_t raxOffset =
                registerStorageOffset(architecture, 0, 8);
            std::string targetExpr = registerName(architecture, 0);
            const auto raxDef = regExpr.find(raxOffset);
            if (raxDef != regExpr.end() &&
                inlineableExpression(raxDef->second))
                targetExpr = stripParens(raxDef->second.text);
            args = targetExpr;
        }
        const auto signature = signatureOf
                                   ? signatureOf(static_cast<uint64_t>(target))
                                   : std::optional<FunctionSignature>{};
        const size_t argumentCount = signature ? signature->parameters.size() : 8;
        const size_t guardShift = guardSlot ? 1 : 0;
        for (size_t i = guardShift; i < argumentCount; ++i) {
            const size_t p = i - guardShift;  // stub arg index (a1..) for guard slots
            const std::vector<uint64_t> fallback =
                defaultArgumentRegisters(architecture);
            const bool fallbackStackArgument =
                !signature && p >= fallback.size();
            const uint64_t offset = signature
                ? signature->parameters[p].registerOffset
                : fallbackStackArgument ? 0 : fallback[p];
            const bool stackArgument =
                (signature && signature->parameters[p].onStack) ||
                fallbackStackArgument;
            std::string argument;
            if (stackArgument) {
                // A machine CALL pushes its return address before the callee
                // observes SP.  The recovered C++ call does not, so convert
                // the callee-entry stack offset back to the caller's current
                // stack coordinate when reading an outgoing argument.
                int64_t callerStackOffset = 0;
                if (signature) {
                    callerStackOffset = signature->parameters[p].stackOffset;
                } else if (architecture.rfind("x86", 0) == 0) {
                    const bool win64 = architecture.find("win64") !=
                                       std::string::npos;
                    const int64_t word = architecture == "x86" ? 4 : 8;
                    const int64_t firstStackAtEntry = win64 ? 5 * word : word;
                    callerStackOffset = firstStackAtEntry +
                        static_cast<int64_t>(p - fallback.size()) * word;
                } else {
                    callerStackOffset = static_cast<int64_t>(
                        p - fallback.size()) * 8;
                }
                if (architecture.rfind("x86", 0) == 0)
                    callerStackOffset -= architecture == "x86" ? 4 : 8;
                const std::string address =
                    registerName(architecture, stackPointerOffset(architecture)) +
                    " + " + std::to_string(callerStackOffset);
                argument = useRecoveredRuntime
                    ? "recovered_load<std::uint64_t>(" + address + ")"
                    : "*((uint64_t *)(uintptr_t)(" + address + "))";
            } else {
                const uint64_t argumentStorage = registerStorageOffset(
                    architecture, offset, 8);
                std::string text = registerName(architecture, offset);
                const auto definition = regExpr.find(argumentStorage);
                if (definition != regExpr.end() &&
                    inlineableExpression(definition->second))
                    text = stripParens(definition->second.text);
                argument = text;
            }
            if (signature && signature->parameters[p].type.kind == TypeKind::POINTER)
                argument = "(void *)(uintptr_t)" + argument;
            // Phase 10h: a bare constant argument that points at a printable
            // data-segment C string reads naturally as a string literal.
            if (!useRecoveredRuntime && memRead &&
                argument.size() > 2 &&
                std::isdigit(static_cast<unsigned char>(argument[0]))) {
                char* end = nullptr;
                const unsigned long long value =
                    std::strtoull(argument.c_str(), &end, 10);
                if (end && *end == '\0' && value > 0x10000ULL) {
                    const std::string literal =
                        stringLiteralAt(static_cast<uint64_t>(value));
                    if (!literal.empty()) argument = literal;
                }
            }
            args += (i ? ", " : "") + argument;
        }
        const std::string call = fname + "(" + args + ")";
        // Calls can clobber registers and memory. Argument text has already
        // been captured; no pre-call definition is valid for later inlining.
        regExpr.clear();
        regConst.clear();
        if (signature && signature->returnType.kind == TypeKind::VOID_TYPE)
            line(call + ";");
        else
            pending.emplace_back(returnRegisterOffset(architecture),
                                 CExpr{call, 8, false});
        return true;
    }

    // returns the stack-slot offset if the address varnode is sp+const
    // (or, with the stack model, rbp+const relative to the entry rsp)
    bool slotOf(const PcodeInsn& pi, uint64_t addrId, int64_t& off) const {
        const Varnode* v = pi.find(addrId);
        if (!v) return false;
        const uint64_t spOffset = stackPointerOffset(architecture);
        const uint64_t bpOffset = framePointerOffset(architecture);
        const bool fpActive =
            stackModel && stackModel->hasFramePointer;
        auto baseOf = [&](const Varnode* n, int64_t& bias) {
            if (!n || n->kind != Varnode::REGISTER) return false;
            if (n->offset == spOffset) { bias = spBias; return true; }
            if (fpActive && n->offset == bpOffset) {
                bias = stackModel->frameBaseOffset;
                return true;
            }
            return false;
        };
        if (v->kind == Varnode::REGISTER) {
            int64_t bias = 0;
            if (baseOf(v, bias)) { off = bias; return true; }
            return false;
        }
        if (v->kind != Varnode::UNIQUE) return false;
        // find the defining INT_ADD(sp|bp, const)
        for (const auto& op : pi.ops) {
            if (op.out != addrId) continue;
            if (op.op != POp::INT_ADD && op.op != POp::INT_SUB) return false;
            const Varnode* a = pi.find(op.in0);
            const Varnode* b = pi.find(op.in1);
            int64_t baseBias = 0;
            const Varnode* cv = nullptr;
            if (baseOf(a, baseBias)) cv = b;
            else if (baseOf(b, baseBias)) cv = a;
            if (!cv || cv->kind != Varnode::CONST) return false;
            const int64_t k = static_cast<int64_t>(cv->offset);
            off = baseBias + (op.op == POp::INT_SUB ? -k : k);
            return true;
        }
        return false;
    }

    void emit() {
        std::map<const Varnode*, CExpr> temps;
        hasCond = false;
        regConst.clear();
        pending.clear();
        regExpr.clear();
        if (entryBlock) {
            paramIndex.clear();
            paramDefined.clear();
            if (architecture.rfind("x86", 0) == 0) {
                const bool win64 =
                    architecture.find("win64") != std::string::npos;
                if (win64) {
                    paramIndex[1 * 8] = 1;
                    paramIndex[2 * 8] = 2;
                    paramIndex[8 * 8] = 3;
                    paramIndex[9 * 8] = 4;
                } else {
                    paramIndex[7 * 8] = 1;
                    paramIndex[6 * 8] = 2;
                    paramIndex[2 * 8] = 3;
                    paramIndex[1 * 8] = 4;
                    paramIndex[8 * 8] = 5;
                    paramIndex[9 * 8] = 6;
                }
            }
            // Phase 10d: infer each parameter's width from entry-block
            // references (e.g. (uint32_t)(param1) -> 32-bit) so the comment
            // carries the ABI usage evidence for downstream binding.
            std::map<int, int> paramWidth; // param# -> narrowest reference
            {
                std::set<int> definedParams;
                for (const auto& pi : blk_.insns) {
                    for (const auto& op : pi.ops) {
                        const Varnode* out = pi.find(op.out);
                        if (out && out->kind == Varnode::REGISTER) {
                            const uint64_t storage = registerStorageOffset(
                                architecture, out->offset, out->size);
                            const auto pit = paramIndex.find(storage);
                            if (pit != paramIndex.end())
                                definedParams.insert(pit->second);
                        }
                        for (const uint64_t input :
                             {op.in0, op.in1, op.in2}) {
                            const Varnode* v = pi.find(input);
                            if (!v || v->kind != Varnode::REGISTER) continue;
                            const uint64_t storage = registerStorageOffset(
                                architecture, v->offset, v->size);
                            const auto pit = paramIndex.find(storage);
                            if (pit == paramIndex.end()) continue;
                            if (definedParams.count(pit->second)) continue;
                            int& w = paramWidth[pit->second];
                            if (w == 0 || v->size < w) w = v->size;
                        }
                    }
                }
            }
            std::string annotation;
            for (const auto& param : paramIndex) {
                std::string entry = "param" +
                    std::to_string(param.second) + "=" +
                    registerName(architecture, param.first, 8);
                const auto wit = paramWidth.find(param.second);
                if (wit != paramWidth.end() && wit->second < 8)
                    entry += " (" + std::string(uCast(wit->second)) + ")";
                annotation += annotation.empty() ? entry : ", " + entry;
            }
            if (!annotation.empty())
                line("// params: " + annotation);
        }

        auto exprOfV = [&](const Varnode* v) -> CExpr {
            if (!v) return CExpr{"0", 8, true};
            if (v->kind == Varnode::CONST) {
                CExpr c{fmtConst(v->offset, v->size), v->size, true};
                // fmtConst emits a signed decimal token (int64_t for
                // 8-byte values, int32_t otherwise).
                c.ctype = v->size == 8 ? "int64_t" : "int32_t";
                return c;
            }
            if (v->kind == Varnode::REGISTER) {
                if (architecture.rfind("riscv", 0) == 0 && v->offset == 0)
                    return CExpr{"0", v->size, true}; // architectural zero
                uint64_t storageOffset = v->offset;
                unsigned shift = 0;
                std::string name =
                    registerName(architecture, v->offset, v->size);
                std::string text = name;
                std::string ctype = v->size == 8 ? "int64_t"
                                                 : std::string(uCast(v->size));
                if (x86GprSlice(architecture, v->offset, v->size,
                                storageOffset, shift)) {
                    name = registerName(architecture, storageOffset, 8);
                    ctype = "int64_t";
                    if (entryBlock) {
                        const auto param = paramIndex.find(storageOffset);
                        if (param != paramIndex.end() &&
                            !paramDefined.count(storageOffset))
                            name = "param" + std::to_string(param->second);
                    }
                    if (v->size < 8 || shift) {
                        const std::string shifted = shift
                            ? name + " >> " + std::to_string(shift) : name;
                        text = "((" + std::string(uCast(v->size)) + ")(" +
                               shifted + "))";
                        ctype = uCast(v->size);
                    } else {
                        text = name;
                    }
                }
                CExpr expression{text, v->size, false};
                expression.ctype = ctype;
                expression.registerRefs[storageOffset].insert(name);
                return expression;
            }
            auto it = temps.find(v);
            if (it != temps.end()) return it->second;
            return CExpr{"0 /* unknown */", v->size, false};
        };
        auto scalarFloat = [&](const CExpr& expression, const Varnode* node,
                               int bits) {
            const std::string type = bits == 32 ? "float" : "double";
            const bool vector = node &&
                (node->size == 16 || node->size == 32 || node->size == 64);
            if (vector)
                return "recovered_vector_scalar<" + type + ">(" +
                       stripParens(expression.text) + ")";
            if (expression.floating) return stripParens(expression.text);
            return "recovered_float_from_bits<" + type + ">(" +
                   stripParens(expression.text) + ")";
        };

        auto emitX86String = [&](const PcodeInsn& pi, const PcodeOp& op) {
            // X86_STRING has several architectural outputs and therefore is
            // intentionally represented as one side-effecting p-code op.
            // Materialize all of those effects here instead of silently
            // dropping REP MOVS/STOS/CMPS/LODS/SCAS during C++ emission.
            const unsigned operation = op.aux & 0x0fU;
            const unsigned width = (op.aux >> 4) & 0x0fU;
            const unsigned repeat = (op.aux >> 8) & 0x03U;
            if (architecture.rfind("x86", 0) != 0 || operation < 1 ||
                operation > 5 ||
                (width != 1 && width != 2 && width != 4 && width != 8)) {
                line("/* unsupported string instruction */");
                return;
            }

            const std::string suffix = std::to_string(pi.addr);
            const std::string count = "recovered_string_count_" + suffix;
            const std::string lhs = "recovered_string_lhs_" + suffix;
            const std::string rhs = "recovered_string_rhs_" + suffix;
            const std::string result = "recovered_string_result_" + suffix;
            const std::string type = uCast(static_cast<int>(width));
            const std::string mask = width == 8
                ? "UINT64_MAX"
                : std::to_string((uint64_t{1} << (width * 8)) - 1) + "ULL";
            auto load = [&](const std::string& address) {
                if (useRecoveredRuntime)
                    return "recovered_load<" + type + ">(" + address + ")";
                return "*((" + type + " *)(uintptr_t)(" + address + "))";
            };
            auto store = [&](const std::string& address,
                             const std::string& value) {
                if (useRecoveredRuntime)
                    return "recovered_store<" + type + ">(" + address + ", " +
                           value + ");";
                return "*((" + type + " *)(uintptr_t)(" + address + ")) = " +
                       value + ";";
            };
            auto advance = [&](const char* reg) {
                line(std::string(reg) + " = " + reg +
                     " + (r4102 != 0 ? static_cast<uint64_t>(-" +
                     std::to_string(width) + "LL) : " +
                     std::to_string(width) + "ULL);");
            };

            line("{");
            ++indent;
            line("uint64_t " + count + " = " +
                 (repeat ? "rcx" : "1ULL") + ";");
            line("while (" + count + " != 0) {");
            ++indent;
            if (operation == 1) { // MOVS
                line("const uint64_t " + lhs + " = " + load("rsi") + ";");
                line(store("rdi", lhs));
            } else if (operation == 2) { // CMPS
                line("const uint64_t " + lhs + " = " + load("rsi") + ";");
                line("const uint64_t " + rhs + " = " + load("rdi") + ";");
            } else if (operation == 3) { // STOS
                line(store("rdi", "static_cast<" + type + ">(rax)"));
            } else if (operation == 4) { // LODS
                line("const uint64_t " + lhs + " = " + load("rsi") + ";");
                line(x86RegisterWrite(architecture, 0, static_cast<int>(width),
                                      lhs) + ";");
            } else { // SCAS
                line("const uint64_t " + lhs + " = static_cast<" + type +
                     ">(rax);");
                line("const uint64_t " + rhs + " = " + load("rdi") + ";");
            }

            if (operation == 2 || operation == 5) {
                line("const uint64_t " + result + " = (" + lhs + " - " + rhs +
                     ") & " + mask + ";");
                line("r4096 = " + lhs + " < " + rhs + ";");
                line("r4097 = (__builtin_parity((unsigned)(" + result +
                     ") & 0xffU) == 0);");
                line("r4098 = ((" + lhs + " ^ " + rhs + " ^ " + result +
                     ") >> 4) & 1U;");
                line("r4099 = " + result + " == 0;");
                line("r4100 = (" + result + " >> " +
                     std::to_string(width * 8 - 1) + ") & 1U;");
                line("r4101 = (((" + lhs + " ^ " + rhs + ") & (" + lhs +
                     " ^ " + result + ")) >> " +
                     std::to_string(width * 8 - 1) + ") & 1U;");
            }

            if (operation == 1 || operation == 2 || operation == 4)
                advance("rsi");
            if (operation == 1 || operation == 2 || operation == 3 ||
                operation == 5)
                advance("rdi");
            if (repeat) {
                line("--" + count + ";");
                line("rcx = " + count + ";");
            } else {
                line(count + " = 0;");
            }
            if ((operation == 2 || operation == 5) && repeat == 2)
                line("if (r4099 == 0) break;");
            if ((operation == 2 || operation == 5) && repeat == 3)
                line("if (r4099 != 0) break;");
            --indent;
            line("}");
            --indent;
            line("}");

            // The instruction invalidates any constants learned for its
            // implicit register outputs before the next instruction.
            if (repeat) regConst.erase(8); // RCX
            if (operation == 1 || operation == 2 || operation == 4)
                regConst.erase(48); // RSI
            if (operation == 1 || operation == 2 || operation == 3 ||
                operation == 5)
                regConst.erase(56); // RDI
            if (operation == 4) regConst.erase(0); // RAX
            // These writes bypass pending, including comparison flags and
            // entry-parameter aliases. Conservatively forget all expressions.
            regExpr.clear();
            if (repeat) paramDefined.insert(8);
            if (operation == 1 || operation == 2 || operation == 4)
                paramDefined.insert(48);
            if (operation == 1 || operation == 2 || operation == 3 || operation == 5)
                paramDefined.insert(56);
        };

        for (size_t piIndex = 0; piIndex < blk_.insns.size(); ++piIndex) {
            const auto& pi = blk_.insns[piIndex];
            dropRspWrite = false; // Phase 10f: per-instruction fold flag
            for (const auto& op : pi.ops) {
                if (op.op == POp::CBRANCH) {
                    const Varnode* condition = pi.find(op.in1);
                    // Native output need not materialize an EFLAGS bit just
                    // to branch on it.  Keep the executable recovered view
                    // conservative, but in the source-facing view substitute
                    // the p-code expression which last defined CF/ZF/SF/OF.
                    // This turns `if (r4096 != 0)` into the original
                    // comparison expression while preserving the flag model
                    // for ADC/SBB/CMOV and the runtime oracle.
                    if (!useRecoveredRuntime && condition &&
                        condition->kind == Varnode::REGISTER &&
                        condition->offset >= 4096 && condition->offset <= 4101) {
                        const auto definition = regExpr.find(condition->offset);
                        cond = definition != regExpr.end() &&
                               inlineableExpression(definition->second)
                            ? stripParens(definition->second.text)
                            : stripParens(exprOfV(condition).text);
                    } else {
                        cond = stripParens(exprOfV(condition).text);
                    }
                    if (!useRecoveredRuntime) {
                        // CBRANCH normally consumes a one-byte UNIQUE made
                        // from a flag (for example INT_NOTEQUAL(CF, 0)), so
                        // substitute flags occurring inside that expression
                        // too, not only a direct register operand.
                        for (uint64_t flag = 4096; flag <= 4101; ++flag) {
                            const auto definition = regExpr.find(flag);
                            if (definition == regExpr.end() ||
                                !inlineableExpression(definition->second)) continue;
                            const std::string name = registerName(
                                architecture, flag, 1);
                            size_t at = 0;
                            while ((at = cond.find(name, at)) !=
                                   std::string::npos) {
                                const bool before = at == 0 ||
                                    (!std::isalnum(static_cast<unsigned char>(cond[at - 1])) && cond[at - 1] != '_');
                                const size_t afterAt = at + name.size();
                                const bool after = afterAt == cond.size() ||
                                    (!std::isalnum(static_cast<unsigned char>(cond[afterAt])) && cond[afterAt] != '_');
                                if (!before || !after) { at = afterAt; continue; }
                                const std::string replacement = "(" +
                                    stripParens(definition->second.text) + ")";
                                cond.replace(at, name.size(), replacement);
                                at += replacement.size();
                            }
                        }
                    }
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
                if (op.op == POp::TRAP) {
                    line("__builtin_trap();");
                    continue;
                }
                if (op.op == POp::SYSCALL) {
                    line("/* system call: ABI-specific clobbers */");
                    continue;
                }
                if (op.op == POp::X86_STRING) {
                    emitX86String(pi, op);
                    continue;
                }
                if (op.op == POp::CALL || op.op == POp::CALLIND) {
                    if (!emitCall(pi, op.in0)) {
                        const Varnode* targetNode = pi.find(op.in0);
                        std::string target = exprOfV(targetNode).text;
                        if (op.op == POp::CALLIND && targetNode &&
                            targetNode->kind == Varnode::REGISTER &&
                            architecture.rfind("x86", 0) == 0) {
                            // An x86 indirect call through a 32-bit
                            // register view (mov esi, eax; call rsi)
                            // still targets the full 64-bit register.
                            // exprOfV slices e.g. esi to (uint32_t)(rsi)
                            // which truncates a valid 64-bit pointer.
                            // Use the full register name instead.
                            unsigned storageOffset = 0;
                            unsigned shift = 0;
                            uint64_t storageOffset64 = 0;
                            if (!x86GprSlice(architecture, targetNode->offset,
                                             targetNode->size, storageOffset64,
                                             shift)) {
                                storageOffset64 = targetNode->offset;
                            }
                            target = registerName(architecture, storageOffset64,
                                                  8);
                        }
                        if (op.op == POp::CALLIND) {
                            // An indirect call must forward the current ABI
                            // argument registers as parameters; the C++
                            // compiler treats the values as dead otherwise
                            // and the callee observes stale register
                            // contents (e.g. rcx left over from a
                            // recovered_load).  Variadic forwarding keeps
                            // every live register visible to the call.
                            const auto& abiRegs =
                                defaultArgumentRegisters(architecture);
                            std::string forwardArgs;
                            for (size_t ai = 0; ai < abiRegs.size(); ++ai) {
                                forwardArgs +=
                                    (ai ? ", " : "") +
                                    registerName(architecture, abiRegs[ai]);
                            }
                            if (useRecoveredRuntime) {
                                // Route through the recovered dispatch
                                // table: the target is an original-image
                                // address (vtable/init-table slot value)
                                // that must reach the recovered C++
                                // function, not mapped image data.
                                // Forward stack-argument slots recorded by
                                // preceding recovered_store(rsp + K, v)
                                // writes as a4..a7; x64 passes the 5th+
                                // argument on the stack and the callee
                                // would otherwise read garbage.
                                std::string stackArgs;
                                static const int64_t argOffsets[] = {
                                    32, 40, 48, 56};
                                for (const int64_t off : argOffsets) {
                                    const auto it = callArgSlots_.find(off);
                                    stackArgs += ", " +
                                        (it != callArgSlots_.end()
                                             ? it->second : std::string("0"));
                                }
                                callArgSlots_.clear();
                                line(registerName(
                                         architecture,
                                         returnRegisterOffset(architecture)) +
                                     " = recovered_dispatch(" + target + ", " +
                                     forwardArgs + stackArgs + ");");
                            } else {
                                std::string stackArgs;
                                static const int64_t argOffsets[] = {
                                    32, 40, 48, 56};
                                for (const int64_t off : argOffsets) {
                                    const auto it = callArgSlots_.find(off);
                                    stackArgs += ", " +
                                        (it != callArgSlots_.end()
                                             ? it->second : std::string("0"));
                                }
                                callArgSlots_.clear();
                                line(registerName(
                                         architecture,
                                         returnRegisterOffset(architecture)) +
                                     " = ((uint64_t (*)(...))(uintptr_t)" +
                                     target + ")(" + forwardArgs + stackArgs +
                                     ");");
                            }
                        } else {
                            line("/* call " + target + " */");
                        }
                    }
                    regExpr.clear();
                    regConst.clear();
                    continue;
                }
                const Varnode* vo = pi.find(op.out);
                if (!vo) {
                    if (op.op == POp::STORE) {
                        int64_t slot = 0;
                        const Varnode* vs = pi.find(op.in2);
                        if (slotOf(pi, op.in0, slot)) {
                        // Phase 10f: fold a confirmed push slot into a plain
                        // saved_<slot> variable; flush drops the paired rsp
                        // write so no simulated stack movement remains.
                        int64_t piDelta = 0;
                        if (!useRecoveredRuntime && pushSlots &&
                            piRspDelta(pi, architecture, piDelta) &&
                            piDelta == -8) {
                            const auto saved = pushSlots->find(slot);
                            if (saved != pushSlots->end()) {
                                line(saved->second.savedName + " = " +
                                     stripParens(
                                         exprOfV(pi.find(op.in2)).text) +
                                     ";");
                                dropRspWrite = true;
                                continue;
                            }
                        }
                            const StackSlot* ss =
                                stackModel ? stackModel->slotAt(slot)
                                           : nullptr;
                            if (ss && ss->promoted) {
                                line(ss->variableName + " = " +
                                     stripParens(exprOfV(pi.find(op.in2)).text) +
                                     ";");
                            } else if (!useRecoveredRuntime) {
                                line(localName(slot) + " = " +
                                     stripParens(exprOfV(pi.find(op.in2)).text) +
                                     ";");
                            } else {
                                const CExpr a = exprOfV(pi.find(op.in0));
                                const CExpr v = exprOfV(pi.find(op.in2));
                                const Varnode* stored = pi.find(op.in2);
                                line("recovered_store<" +
                                     std::string(uCast(stored ? stored->size : 8)) +
                                     ">(" + stripParens(a.text) + ", " +
                                     stripParens(v.text) + ");");
                                // Track writes to x64 stack-argument slots
                                // (rsp+0x20..0x38) so a following CALLIND can
                                // forward them as a4..a7 instead of 0s.
                                if (useRecoveredRuntime) {
                                    static const int64_t argOffsets[] = {
                                        32, 40, 48, 56};
                                    const std::string addr = stripParens(a.text);
                                    for (const int64_t off : argOffsets) {
                                        if (addr == "rsp + " +
                                            std::to_string(off))
                                            callArgSlots_[off] =
                                                stripParens(v.text);
                                    }
                                }
                            }
                        } else {
                            const CExpr a = exprOfV(pi.find(op.in0));
                            const CExpr v = exprOfV(pi.find(op.in2));
                            if (useRecoveredRuntime) {
                                const Varnode* stored = pi.find(op.in2);
                                line("recovered_store<" +
                                     std::string(uCast(stored ? stored->size : 8)) +
                                     ">(" + stripParens(a.text) + ", " +
                                     stripParens(v.text) + ");");
                            } else if (globals) {
                                // Phase 8: name constant-address accesses.
                                const Varnode* addrNode = pi.find(op.in0);
                                if (addrNode &&
                                    addrNode->kind == Varnode::CONST) {
                                    const GlobalObject* object =
                                        globals->objectAt(addrNode->offset);
                                    if (object) {
                                        line("*((" +
                                             std::string(uCast(
                                                 vs ? vs->size : 8)) +
                                             " *)(uintptr_t)(" +
                                             object->name + ")) = " +
                                             stripParens(v.text) + ";");
                                        continue;
                                    }
                                    // Phase 10h: object-internal stores.
                                    uint64_t offset = 0;
                                    object = globals->objectContaining(
                                        addrNode->offset, offset);
                                    if (object && offset != 0) {
                                        line("*((" +
                                             std::string(uCast(
                                                 vs ? vs->size : 8)) +
                                             " *)(uintptr_t)(" +
                                             object->name + " + " +
                                             std::to_string(offset) +
                                             ")) = " + stripParens(v.text) +
                                             ";");
                                        continue;
                                    }
                                }
                                line("*((" +
                                     std::string(uCast(vs ? vs->size : 8)) +
                                     " *)(" + stripParens(a.text) + ")) = " +
                                     stripParens(v.text) + ";");
                            } else {
                                line("*((" +
                                     std::string(uCast(vs ? vs->size : 8)) +
                                     " *)(" + stripParens(a.text) + ")) = " +
                                     stripParens(v.text) + ";");
                            }
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
                    if (op.op == POp::INT_ADD && b.isConst && !a.isConst) {
                        const int64_t n = static_cast<int64_t>(
                            std::strtoll(b.text.c_str(), nullptr, 10));
                        if (n < 0 && n != std::numeric_limits<int64_t>::min()) {
                            c = "-";
                            b.text = std::to_string(-n);
                        }
                    }
                    if (a.isConst && b.isConst) {
                        const uint64_t x = std::strtoull(a.text.c_str(), nullptr, 10);
                        const uint64_t y = std::strtoull(b.text.c_str(), nullptr, 10);
                        uint64_t z = 0;
                        switch (op.op) {
                        case POp::INT_ADD: z = x + y; break;
                        case POp::INT_SUB: z = x - y; break;
                        case POp::INT_MULT: z = x * y; break;
                        case POp::INT_AND: z = x & y; break;
                        case POp::INT_OR: z = x | y; break;
                        case POp::INT_XOR: z = x ^ y; break;
                        default: break;
                        }
                        r.text = std::to_string(static_cast<int64_t>(z));
                        r.size = vo->size;
                        r.isConst = true;
                        if (z == (uint64_t{1} << 63)) {
                            // A decimal token 9223372036854775808 is not a
                            // signed C++ literal; form INT64_MIN legally.
                            r.text = "(-9223372036854775807LL - 1)";
                            r.isConst = false; // not a single numeric token
                        }
                    } else if (b.isConst && b.text == "0") {
                        if (op.op == POp::INT_MULT ||
                            op.op == POp::INT_AND)
                            r = b;
                        else
                            r = a;
                    } else if (a.isConst && a.text == "0") {
                        if (op.op == POp::INT_MULT ||
                            op.op == POp::INT_AND) {
                            r = a;
                        } else if (op.op == POp::INT_SUB) {
                            r.text = "-(" + stripParens(b.text) + ")";
                            r.size = vo->size;
                        } else {
                            r = b;
                        }
                    } else if (a.text == b.text && !a.text.empty() &&
                               (op.op == POp::INT_XOR ||
                                op.op == POp::INT_SUB)) {
                        // Phase 10e: x ^ x == 0, x - x == 0 (side-effect
                        // free expressions, e.g. xor rcx,rcx clearing).
                        r.text = "0";
                        r.size = vo->size;
                        r.isConst = true;
                    } else {
                        r.text = "(" + a.text + " " + c + " " + b.text + ")";
                        if (op.op == POp::INT_MULT && vo->size <= 8) {
                            // uint8_t/uint16_t promote to signed int in C++.
                            // P-code multiplication instead wraps at its
                            // destination width and must never overflow int.
                            r.text = "((" + std::string(uCast(vo->size)) +
                                ")(" + castTo(a, "uint64_t") + " * " +
                                castTo(b, "uint64_t") + "))";
                            r.ctype = uCast(vo->size);
                        }
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
                    const Varnode* input = pi.find(op.in0);
                    const int width = input ? input->size : vo->size;
                    if (width > 8) {
                        // Wide/vector operations have separate lowering;
                        // do not treat them as signed 64-bit scalars here.
                        r.text = "(" + a.text + " " + c + " " + b.text + ")";
                        r.size = vo->size;
                        break;
                    }
                    const bool arithmetic = op.op == POp::INT_SRIGHT;
                    // P-code shifts use the input width, not C integer
                    // promotions. In particular SAR must sign-extend its
                    // operand and SHL on a byte must not shift signed int.
                    // castTo() already presents the operand at the input
                    // width; the final 64-bit presentation wrap is added
                    // here.  It is elided only when the text already
                    // carries that exact cast - the cast is load-bearing
                    // for ">>" signedness, so the ctype-metadata path
                    // (a plain uint64_t-declared register named like an
                    // int64_t) must NOT elide it.
                    const std::string widthTyped = arithmetic
                        ? castTo(a, cCast(width))
                        : castTo(a, uCast(width));
                    const std::string operand = "(" +
                        castTo(CExpr{widthTyped, 8, false, false, ""},
                               arithmetic ? "int64_t" : "uint64_t") + ")";
                    // Constant in-range counts need no guard: the runtime
                    // ternary only models count >= width, which cannot
                    // happen for a folded constant below that bound.
                    int64_t constCount = -1;
                    if (b.isConst) {
                        const int64_t n =
                            std::strtoll(b.text.c_str(), nullptr, 10);
                        if (n >= 0 && n < static_cast<int64_t>(width) * 8)
                            constCount = n;
                    }
                    if (constCount >= 0) {
                        r.text = "(" + operand + " " + c + " " +
                                 std::to_string(constCount) + ")";
                    } else {
                        const std::string count = "(uint64_t)(" + b.text + ")";
                        const std::string outside = arithmetic
                            ? "(" + operand + " < 0 ? -1 : 0)" : "0";
                        r.text = "(" + count + " >= " +
                                 std::to_string(width * 8) +
                                 " ? " + outside + " : (" + operand + " " +
                                 c + " " + count + "))";
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::INT_DIV:
                case POp::INT_SDIV:
                case POp::INT_REM:
                case POp::INT_SREM: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    const bool signedOperation = op.op == POp::INT_SDIV ||
                                                 op.op == POp::INT_SREM;
                    const bool remainder = op.op == POp::INT_REM ||
                                           op.op == POp::INT_SREM;
                    if (a.isConst && b.isConst) {
                        const uint64_t x = std::strtoull(a.text.c_str(), nullptr, 10);
                        const uint64_t y = std::strtoull(b.text.c_str(), nullptr, 10);
                        if (!y) {
                            r.text = "0";
                        } else if (signedOperation) {
                            const int64_t sx = static_cast<int64_t>(x);
                            const int64_t sy = static_cast<int64_t>(y);
                            // Avoid C++'s sole signed division overflow case;
                            // the architecture raises a fault and therefore
                            // has no ordinary result to materialize here.
                            if (sx == std::numeric_limits<int64_t>::min() && sy == -1)
                                r.text = "0";
                            else
                                r.text = std::to_string(remainder ? sx % sy : sx / sy);
                        } else {
                            r.text = std::to_string(remainder ? x % y : x / y);
                        }
                        r.isConst = true;
                    } else {
                        const Varnode* input = pi.find(op.in0);
                        const std::string cast = signedOperation
                            ? std::string(cCast(input ? input->size : vo->size))
                            : std::string(uCast(input ? input->size : vo->size));
                        const std::string x = castTo(a, cast);
                        const std::string y = castTo(b, cast);
                        // A nonzero constant divisor can never trip the
                        // divide-by-zero guard; -1 is kept guarded for
                        // signed ops because INT64_MIN / -1 overflows in C
                        // (the architecture faults and has no result there).
                        const uint64_t constY =
                            b.isConst
                                ? std::strtoull(b.text.c_str(), nullptr, 10)
                                : 0;
                        const bool constantDivisor =
                            b.isConst && constY != 0 &&
                            !(signedOperation &&
                              static_cast<int64_t>(constY) == -1);
                        if (constantDivisor) {
                            r.text = "(" + x + " " +
                                     (remainder ? "%" : "/") + " " + y + ")";
                        } else {
                            r.text = "((" + y + ") != 0 ? (" + x +
                                     " " + (remainder ? "%" : "/") + " " +
                                     y + ") : 0)";
                        }
                    }
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
                    const int width = vs ? vs->size : 8;
                    r.size = vo->size;
                    r.ctype = "uint64_t";
                    if (width >= 8) {
                        // Zero-extension from an already 64-bit value is the
                        // identity; keep the value presented as uint64_t so
                        // downstream unsigned comparisons stay unsigned.
                        r.text = castTo(a, "uint64_t");
                        break;
                    }
                    if (a.isConst) {
                        const uint64_t mask = (uint64_t{1} << (width * 8)) - 1;
                        const uint64_t value =
                            std::strtoull(a.text.c_str(), nullptr, 10) & mask;
                        r.text = std::to_string(value);
                        r.isConst = true;
                        break;
                    }
                    r.text = "(uint64_t)(" +
                             castTo(a, uCast(width)) + ")";
                    break;
                }
                case POp::INT_SEXT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const Varnode* vs = pi.find(op.in0);
                    const int width = vs ? vs->size : 8;
                    r.size = vo->size;
                    r.ctype = "int64_t";
                    if (width >= 8) {
                        // Sign-extension from an already 64-bit value is the
                        // identity; keep the value presented as int64_t so
                        // downstream signed comparisons stay signed.
                        r.text = castTo(a, "int64_t");
                        break;
                    }
                    if (a.isConst) {
                        const uint64_t mask = (uint64_t{1} << (width * 8)) - 1;
                        uint64_t value =
                            std::strtoull(a.text.c_str(), nullptr, 10) & mask;
                        if (width < 8 && (value & (uint64_t{1} << (width * 8 - 1))))
                            value |= ~mask; // sign-extend
                        r.text = std::to_string(static_cast<int64_t>(value));
                        r.isConst = true;
                        break;
                    }
                    r.text = "(int64_t)(" +
                             castTo(a, cCast(width)) + ")";
                    break;
                }
                case POp::SUBPIECE: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr offset = op.in1
                        ? exprOfV(pi.find(op.in1))
                        : CExpr{"0", 8, true};
                    const Varnode* offsetNode = pi.find(op.in1);
                    const std::string source = "(uint64_t)(" + stripParens(a.text) + ")";
                    std::string shifted = stripParens(a.text);
                    if (offsetNode && offsetNode->isConst()) {
                        shifted = offsetNode->offset == 0 ? stripParens(a.text) :
                            offsetNode->offset >= 8 ? "0" :
                            "(" + source + " >> " + std::to_string(offsetNode->offset * 8) + ")";
                    } else if (op.in1 != 0) {
                        const std::string bytes = "(uint64_t)(" + stripParens(offset.text) + ")";
                        shifted = "(" + bytes + " >= 8 ? 0 : (" + source + " >> (" + bytes + " * 8)))";
                    }
                    r.text = "((" + std::string(uCast(vo->size)) + ")(" +
                             shifted + "))";
                    r.size = vo->size;
                    r.ctype = uCast(vo->size);
                    break;
                }
                case POp::PIECE: {
                    const CExpr high = exprOfV(pi.find(op.in0));
                    const CExpr low = exprOfV(pi.find(op.in1));
                    const Varnode* lowNode = pi.find(op.in1);
                    const int shift = (lowNode ? lowNode->size : 8) * 8;
                    if (shift >= 64) {
                        r.text = stripParens(low.text);
                    } else {
                        r.text = "((" + std::string(uCast(vo->size)) + ")(" +
                            "(" + castTo(high, "uint64_t") +
                            " << " + std::to_string(shift) + ") | " +
                            castTo(low, "uint64_t") + "))";
                    }
                    r.size = vo->size;
                    if (shift >= 64)
                        r.ctype = low.ctype;
                    else
                        r.ctype = uCast(vo->size);
                    break;
                }
                case POp::INT_NEGATE: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "(-(" + stripParens(a.text) + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::BOOL_NEGATE: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "(!(" + stripParens(a.text) + "))";
                    r.size = 1;
                    break;
                }
                case POp::INT_CARRY:
                case POp::INT_SCARRY:
                case POp::INT_SBORROW: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    const Varnode* va = pi.find(op.in0);
                    const int bits = (va ? va->size : 8) * 8;
                    const std::string x = stripParens(a.text);
                    const std::string y = stripParens(b.text);
                    if (op.op == POp::INT_CARRY) {
                        r.text = "((" + std::string(uCast(va ? va->size : 8)) +
                                 ")((" + x + ") + (" + y + ")) < (" + x + "))";
                    } else {
                        const char* arith = op.op == POp::INT_SCARRY ? "+" : "-";
                        const char* left = op.op == POp::INT_SCARRY ? "~" : "";
                        r.text = "(((" + std::string(left) + "((" + x + ") ^ (" + y +
                                 ")) & ((" + x + ") ^ ((" + x + ") " + arith +
                                 " (" + y + ")))) >> " + std::to_string(bits - 1) +
                                 ") & 1)";
                    }
                    r.size = 1;
                    break;
                }
                case POp::INT_MULT_OVERFLOW:
                case POp::INT_SMULT_OVERFLOW: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    r.text = std::string(op.op == POp::INT_SMULT_OVERFLOW
                                             ? "signed_mul_overflow("
                                             : "unsigned_mul_overflow(") +
                             stripParens(a.text) + ", " + stripParens(b.text) + ")";
                    r.size = 1;
                    break;
                }
                case POp::INT_PARITY: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "(__builtin_parity((unsigned)(" + stripParens(a.text) +
                             ") & 0xffU) == 0)";
                    r.size = 1;
                    break;
                }
                case POp::INT_POPCOUNT:
                case POp::INT_COUNT_LEADING_ZERO:
                case POp::INT_COUNT_TRAILING_ZERO: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const Varnode* input = pi.find(op.in0);
                    const std::string x = stripParens(a.text);
                    const int bits = (input ? input->size : 8) * 8;
                    if (op.op == POp::INT_POPCOUNT)
                        r.text = "__builtin_popcountll(" + x + ")";
                    else if (op.op == POp::INT_COUNT_LEADING_ZERO) {
                        // clz/clzll count over the width of their host type,
                        // not the p-code varnode.  Using clzll for EAX, AX or
                        // AL therefore adds 32/48/56 nonexistent high zero
                        // bits.  Select the closest host builtin and remove
                        // its padding so the emitted C preserves the source
                        // operand's architectural width.
                        const bool wide = bits > 32;
                        const int hostBits = wide ? 64 : 32;
                        const std::string builtin = wide
                            ? "__builtin_clzll((unsigned long long)(" + x + "))"
                            : "__builtin_clz((unsigned)(" + x + "))";
                        const std::string adjusted = hostBits == bits
                            ? builtin
                            : "(" + builtin + " - " +
                                  std::to_string(hostBits - bits) + ")";
                        r.text = "(" + x + " ? " + adjusted + " : " +
                                 std::to_string(bits) + ")";
                    }
                    else {
                        const std::string builtin = bits > 32
                            ? "__builtin_ctzll((unsigned long long)(" + x + "))"
                            : "__builtin_ctz((unsigned)(" + x + "))";
                        r.text = "(" + x + " ? " + builtin + " : " +
                                 std::to_string(bits) + ")";
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::FLOAT_EQUAL: case POp::FLOAT_NOTEQUAL:
                case POp::FLOAT_LESS: case POp::FLOAT_LESSEQUAL: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    const int bits = (op.aux & 0x7fff) == 32 ? 32 : 64;
                    const std::string x = scalarFloat(a, pi.find(op.in0), bits);
                    const std::string y = scalarFloat(b, pi.find(op.in1), bits);
                    const char* relation = op.op == POp::FLOAT_EQUAL ? "=="
                                           : op.op == POp::FLOAT_NOTEQUAL ? "!="
                                           : op.op == POp::FLOAT_LESS ? "<" : "<=";
                    r.text = "(" + x + " " + relation + " " + y + ")";
                    r.size = 1;
                    break;
                }
                case POp::FLOAT_NAN: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    const int bits = (op.aux & 0x7fff) == 32 ? 32 : 64;
                    r.text = "(std::isnan(" +
                             scalarFloat(a, pi.find(op.in0), bits) +
                             ") || std::isnan(" +
                             scalarFloat(b, pi.find(op.in1), bits) + "))";
                    r.size = 1;
                    break;
                }
                case POp::FLOAT_ADD: case POp::FLOAT_SUB:
                case POp::FLOAT_MULT: case POp::FLOAT_DIV:
                case POp::FLOAT_MIN: case POp::FLOAT_MAX: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    const int laneBits = (op.aux & 0x7fff) == 64 ? 64 : 32;
                    const std::string scalarType = laneBits == 64 ? "double" : "float";
                    const char* symbol = op.op == POp::FLOAT_ADD ? "+"
                                         : op.op == POp::FLOAT_SUB ? "-"
                                         : op.op == POp::FLOAT_MULT ? "*"
                                         : op.op == POp::FLOAT_DIV ? "/" : "";
                    if ((vo->size == 16 || vo->size == 32 || vo->size == 64) &&
                        (op.aux & 0x8000)) {
                        const std::string x = scalarFloat(a, pi.find(op.in0), laneBits);
                        const std::string y = scalarFloat(b, pi.find(op.in1), laneBits);
                        const std::string computed =
                            op.op == POp::FLOAT_MIN ? "std::fmin(" + x + ", " + y + ")"
                            : op.op == POp::FLOAT_MAX ? "std::fmax(" + x + ", " + y + ")"
                            : "(" + x + " " + symbol + " " + y + ")";
                        r.text = "recovered_vector_replace_scalar<" + scalarType +
                                 ">(" + stripParens(a.text) + ", " + computed + ")";
                    } else if (vo->size == 16 || vo->size == 32 ||
                               vo->size == 64) {
                        const std::string suffix = (op.aux & 0x7fff) == 64 ? "f64" : "f32";
                        r.text = "simd_" + std::string(op.op == POp::FLOAT_ADD ? "add_"
                                                      : op.op == POp::FLOAT_SUB ? "sub_"
                                                      : op.op == POp::FLOAT_MULT ? "mul_"
                                                      : op.op == POp::FLOAT_DIV ? "div_"
                                                      : op.op == POp::FLOAT_MIN ? "min_" : "max_") +
                                 suffix + "(" + stripParens(a.text) + ", " +
                                 stripParens(b.text) + ")";
                    } else {
                        const std::string x = scalarFloat(a, pi.find(op.in0), laneBits);
                        const std::string y = scalarFloat(b, pi.find(op.in1), laneBits);
                        if (op.op == POp::FLOAT_MIN || op.op == POp::FLOAT_MAX)
                            r.text = std::string(op.op == POp::FLOAT_MIN ? "std::fmin(" : "std::fmax(") +
                                     x + ", " + y + ")";
                        else
                            r.text = "(" + x + " " + symbol + " " + y + ")";
                        r.floating = true;
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::FLOAT_NEG: case POp::FLOAT_ABS: case POp::FLOAT_SQRT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const int laneBits = (op.aux & 0x7fff) == 64 ? 64 : 32;
                    const std::string scalarType = laneBits == 64 ? "double" : "float";
                    const std::string x = scalarFloat(a, pi.find(op.in0), laneBits);
                    const std::string computed = op.op == POp::FLOAT_NEG
                        ? "(-(" + x + "))"
                        : op.op == POp::FLOAT_ABS ? "std::fabs(" + x + ")"
                                                  : "std::sqrt(" + x + ")";
                    if ((vo->size == 16 || vo->size == 32 || vo->size == 64) &&
                        (op.aux & 0x8000)) {
                        const CExpr base = op.in1 ? exprOfV(pi.find(op.in1)) : a;
                        r.text = "recovered_vector_replace_scalar<" + scalarType +
                                 ">(" + stripParens(base.text) + ", " + computed + ")";
                    } else {
                        r.text = computed;
                        r.floating = true;
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::FLOAT_INT2FLOAT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const bool single = (op.aux & 0x7fff) == 32;
                    const std::string type = single ? "float" : "double";
                    const std::string converted = "(" + type + ")(int64_t)(" +
                                                  stripParens(a.text) + ")";
                    if (vo->size > 8 && op.in1) {
                        const CExpr base = exprOfV(pi.find(op.in1));
                        r.text = "recovered_vector_replace_scalar<" + type + 
                                 ">(" + stripParens(base.text) + ", " + converted + ")";
                    } else {
                        r.text = converted;
                        r.floating = true;
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::FLOAT_FLOAT2INT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const int sourceBits = (op.aux & 0x7fff) == 32 ? 32 : 64;
                    const std::string x = scalarFloat(a, pi.find(op.in0), sourceBits);
                    r.text = (op.aux & 0x8000) ? "(int64_t)std::trunc(" + x + ")"
                                               : "(int64_t)std::nearbyint(" + x + ")";
                    r.size = vo->size;
                    break;
                }
                case POp::FLOAT_FLOAT2FLOAT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const int sourceBits = (op.aux & 0xff) == 32 ? 32 : 64;
                    const int destinationBits = (op.aux >> 8) & 0x7f;
                    const std::string destinationType = destinationBits == 32
                        ? "float" : "double";
                    const std::string converted = "(" + destinationType + ")(" +
                        scalarFloat(a, pi.find(op.in0), sourceBits) + ")";
                    if (vo->size > 8 && op.in1) {
                        const CExpr base = exprOfV(pi.find(op.in1));
                        r.text = "recovered_vector_replace_scalar<" +
                                 destinationType + ">(" + stripParens(base.text) +
                                 ", " + converted + ")";
                    } else {
                        r.text = converted;
                        r.floating = true;
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_MASK: {
                    const CExpr computed = exprOfV(pi.find(op.in0));
                    const CExpr previous = exprOfV(pi.find(op.in1));
                    const CExpr mask = exprOfV(pi.find(op.in2));
                    r.text = std::string((op.aux & 0x8000)
                                             ? "simd_mask_zero("
                                             : "simd_mask_merge(") +
                             stripParens(computed.text) + ", " +
                             stripParens(previous.text) + ", " +
                             stripParens(mask.text) + ")";
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_EXTRACT: {
                    const CExpr vector = exprOfV(pi.find(op.in0));
                    const CExpr lane = exprOfV(pi.find(op.in1));
                    const Varnode* vectorNode = pi.find(op.in0);
                    const unsigned bits = static_cast<unsigned>(
                        std::max(1, vo->size) * 8);
                    if (vectorNode && vectorNode->size > 8) {
                        r.text = "recovered_vector_extract<" +
                                 std::string(uCast(vo->size)) + ">(" +
                                 stripParens(vector.text) + ", " +
                                 stripParens(lane.text) + ")";
                    } else {
                        r.text = "((" + std::string(uCast(vo->size)) + ")((" +
                                 stripParens(lane.text) + " * " +
                                 std::to_string(bits) + " < 64) ? ((" +
                                 stripParens(vector.text) + ") >> (" +
                                 stripParens(lane.text) + " * " +
                                 std::to_string(bits) + ")) : 0))";
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_INSERT: {
                    const CExpr previous = exprOfV(pi.find(op.in0));
                    const CExpr inserted = exprOfV(pi.find(op.in1));
                    const CExpr lane = exprOfV(pi.find(op.in2));
                    const Varnode* insertedNode = pi.find(op.in1);
                    const unsigned bits = static_cast<unsigned>(
                        std::max(1, insertedNode ? insertedNode->size : 8) * 8);
                    if (vo->size > 8) {
                        const std::string laneType = uCast(
                            insertedNode ? insertedNode->size : 8);
                        r.text = "recovered_vector_insert<" + laneType + ">(" +
                                 stripParens(previous.text) + ", (" + laneType +
                                 ")(" + stripParens(inserted.text) + "), " +
                                 stripParens(lane.text) + ")";
                        r.size = vo->size;
                        break;
                    }
                    const std::string mask = bits >= 64
                        ? "UINT64_MAX"
                        : "((UINT64_C(1) << " + std::to_string(bits) + ") - 1)";
                    const std::string shift = "(" + stripParens(lane.text) +
                                              " * " + std::to_string(bits) + ")";
                    r.text = "((" + shift + " < 64) ? (((" +
                             stripParens(previous.text) + ") & ~((" + mask +
                             ") << " + shift + ")) | (((" +
                             stripParens(inserted.text) + ") & (" + mask +
                             ")) << " + shift + ")) : (" +
                             stripParens(previous.text) + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::INT_NOT: {
                    const CExpr a = exprOfV(pi.find(op.in0));
                    r.text = "(~(" + stripParens(a.text) + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::FLOAT_SCALE: {
                    // x87 fscale: a * 2^b
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const CExpr b = exprOfV(pi.find(op.in1));
                    r.text = "((" + stripParens(a.text) + ") * exp2((" +
                             stripParens(b.text) + ")))";
                    r.size = vo->size;
                    r.floating = true;
                    break;
                }
                case POp::SIMD_PACK: {
                    // packsswb/packuswb/packssdw/packusdw: saturate the
                    // lanes of both sources into half-width destination
                    // lanes.  aux = srcLaneBits | (unsigned ? 0x0100 : 0).
                    // The full 128-bit result is built with insert chains
                    // since the simulated vector holds all 16 bytes.
                    const CExpr lhs = exprOfV(pi.find(op.in0));
                    const CExpr rhs = exprOfV(pi.find(op.in1));
                    const std::string a = stripParens(lhs.text);
                    const std::string b = stripParens(rhs.text);
                    const int srcBits = op.aux & 0xff;
                    const bool us = (op.aux & 0x0100) != 0;
                    const int outBits = srcBits / 2;
                    const int n = 16 / (srcBits / 8);
                    const std::string srcLane =
                        srcBits == 32 ? "int32_t" : "int16_t";
                    const std::string outType =
                        us ? (outBits == 8 ? "uint8_t" : "uint16_t")
                           : (outBits == 8 ? "int8_t" : "int16_t");
                    const int64_t lo = us
                        ? 0
                        : -(static_cast<int64_t>(1) << (outBits - 1));
                    const int64_t hi = us
                        ? ((static_cast<int64_t>(1) << outBits) - 1)
                        : ((static_cast<int64_t>(1) << (outBits - 1)) - 1);
                    auto sat = [&](const std::string& x) {
                        return "((" + x + ") < " + std::to_string(lo) +
                               " ? " + std::to_string(lo) + " : (" + x +
                               ") > " + std::to_string(hi) + " ? " +
                               std::to_string(hi) + " : (" + x + "))";
                    };
                    std::string result = "RecoveredVector<16>{}";
                    for (int i = 0; i < 16 / (outBits / 8); ++i) {
                        const int srcIndex = i < n ? i : i - n;
                        const std::string& src = i < n ? a : b;
                        const std::string value = sat(
                            "recovered_vector_extract<" + srcLane + ">(" +
                            src + ", " + std::to_string(srcIndex) + ")");
                        result = "recovered_vector_insert<" + outType +
                                 ">(" + result + ", " + value + ", " +
                                 std::to_string(i) + ")";
                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_BLEND: {
                    // blendps/blendpd: imm8 selects per-lane whether the
                    // result lane comes from src (bit 1) or stays base.
                    // aux = laneBits (32/64).
                    const CExpr baseExpr = exprOfV(pi.find(op.in0));
                    const CExpr srcExpr = exprOfV(pi.find(op.in1));
                    const std::string base = stripParens(baseExpr.text);
                    const std::string src = stripParens(srcExpr.text);
                    const int laneBits = op.aux & 0xff;
                    const int lanes = 16 / (laneBits / 8);
                    int mask = 0;
                    if (op.in2) {
                        const Varnode* immNode = pi.find(op.in2);
                        if (immNode && immNode->kind == Varnode::CONST)
                            mask = static_cast<int>(immNode->offset & 0xff);
                    }
                    const std::string lane =
                        laneBits == 64 ? "double" : "float";
                    std::string result = base;
                    for (int i = 0; i < lanes; ++i) {
                        if ((mask >> i) & 1) {
                            result =
                                "recovered_vector_replace_scalar<" + lane +
                                ">(" + result +
                                ", recovered_vector_extract<" + lane +
                                ">(" + src + ", " + std::to_string(i) +
                                "))";
                        }
                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_ABS: {
                    // pabsb/pabsw/pabsd: per-lane absolute value.  aux =
                    // laneBits (8/16/32).  Rebuild the full 128-bit vector
                    // with insert chains.
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const std::string source = stripParens(a.text);
                    const int laneBits = op.aux & 0xff;
                    const std::string lane =
                        laneBits == 8   ? "int8_t"
                        : laneBits == 16 ? "int16_t"
                                         : "int32_t";
                    const int lanes = 16 / (laneBits / 8);
                    std::string result = "RecoveredVector<16>{}";
                    for (int i = 0; i < lanes; ++i) {
                        const std::string value =
                            "std::abs(recovered_vector_extract<" + lane +
                            ">(" + source + ", " + std::to_string(i) +
                            "))";
                        result = "recovered_vector_insert<" + lane + ">(" +
                                 result + ", " + value + ", " +
                                 std::to_string(i) + ")";
                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_TEST: {
                    // ptest: aux=0 -> ZF ((a & b) == 0), aux=1 -> CF
                    // ((~a & b) == 0).  Both 64-bit halves must be zero.
                    const CExpr lhs = exprOfV(pi.find(op.in0));
                    const CExpr rhs = exprOfV(pi.find(op.in1));
                    const std::string a = stripParens(lhs.text);
                    const std::string b = stripParens(rhs.text);
                    const bool cf = op.aux != 0;
                    const std::string notPrefix = cf ? "~" : "";
                    const std::string h0 =
                        "(" + notPrefix +
                        "recovered_vector_extract<uint64_t>(" + a +
                        ", 0) & recovered_vector_extract<uint64_t>(" + b +
                        ", 0))";
                    const std::string h1 =
                        "(" + notPrefix +
                        "recovered_vector_extract<uint64_t>(" + a +
                        ", 1) & recovered_vector_extract<uint64_t>(" + b +
                        ", 1))";
                    r.text = "((" + h0 + " == 0) && (" + h1 + " == 0))";
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_ROUND: {
                    // roundsd/roundss/roundpd/roundps: lane-wise rounding
                    // with an explicit x86 mode.  aux = laneBits |
                    // (scalar ? 0x8000 : 0); op.in0 = value, op.in1 =
                    // base (unmodified lanes preserved), op.in2 = mode
                    // immediate (0/8 nearest-even, 1/9 floor, 2/10 ceil,
                    // 3/11 truncate).
                    const CExpr valueExpr = exprOfV(pi.find(op.in0));
                    const CExpr baseExpr = exprOfV(pi.find(op.in1));
                    const std::string value = stripParens(valueExpr.text);
                    const std::string base = stripParens(baseExpr.text);
                    const int laneBits = op.aux & 0xff;
                    const bool scalar = (op.aux & 0x8000) != 0;
                    int mode = 0;
                    if (op.in2) {
                        const Varnode* immNode = pi.find(op.in2);
                        if (immNode && immNode->kind == Varnode::CONST)
                            mode = static_cast<int>(immNode->offset & 0x1f);
                    }
                    std::string fn = "std::rint";
                    if (mode == 1 || mode == 9) fn = "std::floor";
                    else if (mode == 2 || mode == 10) fn = "std::ceil";
                    else if (mode == 3 || mode == 11) fn = "std::trunc";
                    const std::string lane =
                        laneBits == 64 ? "double" : "float";
                    if (scalar) {
                        r.text = "recovered_vector_replace_scalar<" + lane +
                                 ">(" + base + ", " + fn +
                                 "(recovered_vector_scalar<" + lane + ">(" +
                                 value + ")))";
                    } else {
                        const int lanes = 16 / (laneBits / 8);
                        std::string result = base;
                        for (int i = 0; i < lanes; ++i) {
                            result =
                                "recovered_vector_replace_scalar<" + lane +
                                ">(" + result + ", " + fn +
                                "(recovered_vector_extract<" + lane + ">(" +
                                value + ", " + std::to_string(i) + ")))";
                        }
                        r.text = result;
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_FLOAT2INT: {
                    // cvtps2dq/cvttps2dq/cvtpd2dq/cvttpd2dq: float lanes to
                    // int32 lanes.  The low 64-bit window carries the first
                    // two int32 lanes.  C++ float->int truncates, so the
                    // rounding (non-truncate) forms use llround.
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const std::string source = stripParens(a.text);
                    const int sourceBits = op.aux & 0xff;
                    const bool truncate = (op.aux & 0x8000) != 0;
                    const std::string lane =
                        sourceBits == 64 ? "double" : "float";
                    const std::string e0 =
                        "((int32_t)" +
                        (truncate ? std::string() : "llround(") +
                        "recovered_vector_extract<" + lane + ">(" +
                        source + ", 0)" + (truncate ? "" : ")") + ")";
                    const std::string e1 =
                        "((int32_t)" +
                        (truncate ? std::string() : "llround(") +
                        "recovered_vector_extract<" + lane + ">(" +
                        source + ", 1)" + (truncate ? "" : ")") + ")";
                    r.text = "(" + e0 + " | (" + e1 + " << 32))";
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_FP_COMPARE: {
                    // cmpps/cmppd/cmpss/cmpsd: lane-wise predicate masks.
                    // aux = laneBits | (scalar ? 0x8000 : 0); op.in2 is the
                    // x86 predicate immediate.  Emit the low 64-bit window
                    // as a mask (all-ones per true lane).
                    const CExpr lhs = exprOfV(pi.find(op.in0));
                    const CExpr rhs = exprOfV(pi.find(op.in1));
                    const std::string a = stripParens(lhs.text);
                    const std::string b = stripParens(rhs.text);
                    const bool f32 = (op.aux & 0xff) == 32;
                    const bool scalar = (op.aux & 0x8000) != 0;
                    const std::string lane = f32 ? "float" : "double";
                    const Varnode* immNode = pi.find(op.in2);
                    const int imm = immNode && immNode->isConst()
                        ? static_cast<int>(immNode->offset & 0xff) : 0;
                    auto pred = [&](int index) -> std::string {
                        const std::string x =
                            "recovered_vector_extract<" + lane + ">(" +
                            a + ", " + std::to_string(index) + ")";
                        const std::string y =
                            "recovered_vector_extract<" + lane + ">(" +
                            b + ", " + std::to_string(index) + ")";
                        const std::string na = "std::isnan(" + x + ")";
                        const std::string nb = "std::isnan(" + y + ")";
                        switch (imm) {
                        case 0: return "((" + x + ") == (" + y + "))";
                        case 1: return "((" + x + ") < (" + y + "))";
                        case 2: return "((" + x + ") <= (" + y + "))";
                        case 3: return "((" + na + ") || (" + nb + "))";
                        case 4: return "((" + x + ") != (" + y + "))";
                        case 5: return "!((" + x + ") < (" + y + "))";
                        case 6: return "!((" + x + ") <= (" + y + "))";
                        default: return "!((" + na + ") || (" + nb + "))";
                        }
                    };
                    if (scalar) {
                        // comisd/ucomisd-style: the source operand is a
                        // scalar lane (8/4 bytes of bits), not a vector.
                        const std::string x =
                            "recovered_vector_scalar<" + lane + ">(" +
                            a + ")";
                        const std::string y =
                            "recovered_float_from_bits<" + lane + ">(" +
                            b + ")";
                        const std::string na = "std::isnan(" + x + ")";
                        const std::string nb = "std::isnan(" + y + ")";
                        std::string condition;
                        switch (imm) {
                        case 0: condition = "((" + x + ") == (" + y + "))"; break;
                        case 1: condition = "((" + x + ") < (" + y + "))"; break;
                        case 2: condition = "((" + x + ") <= (" + y + "))"; break;
                        case 3: condition = "((" + na + ") || (" + nb + "))"; break;
                        case 4: condition = "((" + x + ") != (" + y + "))"; break;
                        case 5: condition = "!((" + x + ") < (" + y + "))"; break;
                        case 6: condition = "!((" + x + ") <= (" + y + "))"; break;
                        default: condition = "!((" + na + ") || (" + nb + "))"; break;
                        }
                        r.text = "(" + condition + " ? " +
                                 (f32 ? "0xffffffffULL"
                                      : "0xffffffffffffffffULL") +
                                 " : 0)";
                    } else if (f32) {
                        r.text = "((" + pred(0) + " ? 0xffffffffULL : 0) |"
                                 " ((" + pred(1) + " ? 0xffffffffULL : 0)"
                                 " << 32))";
                    } else {
                        r.text = "(" + pred(0) +
                                 " ? 0xffffffffffffffffULL : 0)";
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_UNPACK: {
                    // punpckl*/punpckh* (and SSE float unpcklps/hps/lpd/hpd):
                    // interleave lanes from two sources.  aux encodes
                    // laneBits | (high ? 0x8000 : 0).  The generated C
                    // carries the observable low 64-bit window as an
                    // integer expression (RecoveredVector converts
                    // implicitly).
                    const CExpr left = exprOfV(pi.find(op.in0));
                    const CExpr right = exprOfV(pi.find(op.in1));
                    const std::string a = stripParens(left.text);
                    const std::string b = stripParens(right.text);
                    const int laneBits = op.aux & 0x7fff;
                    const bool high = (op.aux & 0x8000) != 0;
                    if (laneBits >= 64) {
                        // punpcklqdq: window = first source lane; hqdq
                        // = first source's upper lane.
                        r.text = high ? "((" + a + ") >> 32)" : a;
                    } else {
                        const uint64_t mask =
                            (uint64_t{1} << laneBits) - 1;
                        const int per = 32 / laneBits;
                        std::string expr = "(";
                        for (int i = 0; i < per; ++i) {
                            const int srcShift =
                                (high ? 32 : 0) + i * laneBits;
                            const std::string ai =
                                "(((" + a + ") >> " +
                                std::to_string(srcShift) + ") & " +
                                std::to_string(mask) + "ULL)";
                            const std::string bi =
                                "(((" + b + ") >> " +
                                std::to_string(srcShift) + ") & " +
                                std::to_string(mask) + "ULL)";
                            if (i) expr += " | ";
                            expr += ai + " << " +
                                    std::to_string(2 * i * laneBits) +
                                    " | " + bi + " << " +
                                    std::to_string((2 * i + 1) * laneBits);
                        }
                        expr += ")";
                        r.text = expr;
                    }
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_SHUFFLE: {
                    // SHUFPS is the form currently reaching the project
                    // emitter in the Blender corpus.  Its low two result
                    // lanes are selected from the first input by imm[3:0].
                    const CExpr left = exprOfV(pi.find(op.in0));
                    const CExpr control = exprOfV(pi.find(op.in2));
                    const std::string source = stripParens(left.text);
                    const std::string immediate = stripParens(control.text);
                    const std::string first = "((" + immediate + " & 3) < 2 ? ((" +
                        source + ") >> ((" + immediate + " & 3) * 32)) : 0)";
                    const std::string second = "(((" + immediate + " >> 2) & 3) < 2 ? ((" +
                        source + ") >> (((" + immediate + " >> 2) & 3) * 32)) : 0)";
                    r.text = "((" + first + " & UINT64_C(0xffffffff)) | ((" +
                             second + " & UINT64_C(0xffffffff)) << 32))";
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_BYTE_SHIFT: {
                    // Project C currently carries the observable low 64-bit
                    // window of an XMM/YMM/ZMM value.  Preserve byte shifts
                    // within that window and explicitly zero it when the
                    // selected 128-bit source bytes lie above the window.
                    const CExpr source = exprOfV(pi.find(op.in0));
                    const CExpr count = exprOfV(pi.find(op.in1));
                    const std::string x = stripParens(source.text);
                    const std::string n = stripParens(count.text);
                    const bool right = (op.aux & 1U) != 0;
                    r.text = "((" + n + ") < 8 ? ((" + x + ") " +
                             (right ? ">>" : "<<") + " ((" + n +
                             ") * 8)) : 0)";
                    r.size = vo->size;
                    break;
                }
                case POp::INT_BSWAP: {
                    // Byte-swap a GPR-sized value.  vo->size is the operand
                    // width (4 or 8 for the x86 BSWAP family).
                    const CExpr a = exprOfV(pi.find(op.in0));
                    const std::string x = stripParens(a.text);
                    r.text = vo->size >= 8
                        ? "__builtin_bswap64(" + x + ")"
                        : "__builtin_bswap32((uint32_t)(" + x + "))";
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_INT2FLOAT:
                case POp::SIMD_FLOAT2FLOAT: {
                    // Packed lane-wise conversion (cvtdq2pd, cvtps2pd,
                    // cvtpd2ps, ...).  aux = sourceBits | (destBits << 8).
                    // Each source lane is extracted, converted, and inserted
                    // into the destination vector; lanes beyond the source
                    // width stay zero (recovered_vector_extract returns 0
                    // out of range), matching x86 zero-fill semantics.
                    const CExpr source = exprOfV(pi.find(op.in0));
                    const Varnode* sourceNode = pi.find(op.in0);
                    const int sourceBits = (op.aux & 0xff) ? (op.aux & 0xff) : 32;
                    const int destinationBits =
                        ((op.aux >> 8) & 0x7f) ? ((op.aux >> 8) & 0x7f) : 32;
                    const int destinationBytes = destinationBits / 8;
                    const int lanes =
                        std::max(1, vo->size / destinationBytes);
                    const std::string sourceType =
                        op.op == POp::SIMD_INT2FLOAT
                            ? (sourceBits == 32 ? "int32_t" : "int64_t")
                            : (sourceBits == 32 ? "float" : "double");
                    const std::string destinationType =
                        destinationBits == 32 ? "float" : "double";
                    const bool vectorSource =
                        sourceNode && sourceNode->size > 8;
                    const std::string srcText = stripParens(source.text);
                    std::string result = "RecoveredVector<" +
                        std::to_string(vo->size) + ">{}";
                    for (int lane = lanes - 1; lane >= 0; --lane) {
                        std::string laneValue;
                        if (vectorSource) {
                            laneValue = "recovered_vector_extract<" +
                                sourceType + ">(" + srcText + ", " +
                                std::to_string(lane) + ")";
                        } else if (op.op == POp::SIMD_INT2FLOAT) {
                            laneValue = "(" + sourceType +
                                ")((uint64_t)(" + srcText + ") >> " +
                                std::to_string(lane * sourceBits) + ")";
                        } else {
                            laneValue = "recovered_float_from_bits<" +
                                sourceType + ">((uint64_t)(" + srcText +
                                ") >> " + std::to_string(lane * sourceBits) +
                                ")";
                        }
                        std::string converted =
                            op.op == POp::SIMD_INT2FLOAT
                                ? "(" + destinationType + ")(int64_t)(" +
                                      laneValue + ")"
                                : "(" + destinationType + ")(" + laneValue +
                                      ")";
                        result = "recovered_vector_insert<" +
                            destinationType + ">(" + result + ", " +
                            converted + ", " + std::to_string(lane) + ")";
                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_SHIFT: {
                    // Packed lane-wise shift (psllw/d/q, psrlw/d/q,
                    // psraw/d).  aux = laneBits | (right << 8) |
                    // (arithmetic << 9).  Each lane is shifted by the
                    // scalar count; arithmetic right shift keeps sign.
                    const CExpr source = exprOfV(pi.find(op.in0));
                    const CExpr count = exprOfV(pi.find(op.in1));
                    const Varnode* sourceNode = pi.find(op.in0);
                    const unsigned laneBits =
                        (op.aux & 0xffU) ? (op.aux & 0xffU) : 32;
                    const bool right = (op.aux & 0x0100U) != 0;
                    const bool arithmetic = (op.aux & 0x0200U) != 0;
                    const int laneBytes = static_cast<int>(laneBits / 8);
                    const std::string laneType = uCast(laneBytes);
                    const bool vectorSource =
                        sourceNode && sourceNode->size > 8;
                    const std::string sText = stripParens(source.text);
                    const std::string nText = stripParens(count.text);
                    const int lanes =
                        std::max(1, vo->size / laneBytes);
                    std::string result = "RecoveredVector<" +
                        std::to_string(vo->size) + ">{}";
                    for (int lane = lanes - 1; lane >= 0; --lane) {
                        std::string laneValue;
                        if (vectorSource) {
                            laneValue = "recovered_vector_extract<" +
                                laneType + ">(" + sText + ", " +
                                std::to_string(lane) + ")";
                        } else {
                            const unsigned shift = lane * laneBits;
                            const std::string mask =
                                laneBits >= 64
                                    ? "~0ULL"
                                    : "((1ULL << " +
                                          std::to_string(laneBits) +
                                          ") - 1)";
                            laneValue = "(" + laneType + ")((" + sText +
                                ") >> " + std::to_string(shift) +
                                " & " + mask + ")";
                        }
                        std::string shifted;
                        if (right) {
                            if (arithmetic) {
                                shifted = "((" + laneType + ")(" +
                                    laneValue + ") >> ((" + nText +
                                    ") & " + std::to_string(laneBits - 1) +
                                    "))";
                            } else {
                                shifted = "(" + laneType + ")((" +
                                    laneValue + ") >> ((" + nText +
                                    ") & " + std::to_string(laneBits - 1) +
                                    "))";
                            }
                        } else {
                            shifted = "(" + laneType + ")((" +
                                laneValue + ") << ((" + nText +
                                ") & " + std::to_string(laneBits - 1) +
                                "))";
                        }
                        result = "recovered_vector_insert<" + laneType +
                                 ">(" + result + ", " + shifted + ", " +
                                 std::to_string(lane) + ")";
                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_COMPARE: {
                    // Packed lane-wise integer compare (pcmpeqb/w/d/q,
                    // pcmpgtb/w/d/q, and VEX/EVEX forms).  aux = laneBits |
                    // (signed << 8) | (greater << 9).  Each lane yields
                    // all-ones when the predicate holds, zero otherwise,
                    // matching x86 mask semantics.  The project C model
                    // carries only the low 64-bit window, so lanes beyond
                    // the window are dropped (extract returns 0 for them).
                    const CExpr lhs = exprOfV(pi.find(op.in0));
                    const CExpr rhs = exprOfV(pi.find(op.in1));
                    const Varnode* lhsNode = pi.find(op.in0);
                    const unsigned laneBits =
                        (op.aux & 0xffU) ? (op.aux & 0xffU) : 8;
                    const bool signedCompare = (op.aux & 0x0100U) != 0;
                    const bool greater = (op.aux & 0x0200U) != 0;
                    const int laneBytes = static_cast<int>(laneBits / 8);
                    const std::string laneType = uCast(laneBytes);
                    const bool vectorSource =
                        lhsNode && lhsNode->size > 8;
                    const std::string lText = stripParens(lhs.text);
                    const std::string rText = stripParens(rhs.text);
                    const std::string zeroLane =
                        "(" + laneType + ")0";
                    const std::string onesLane =
                        "(" + laneType + ")~(" + laneType +
                        ")0";
                    std::string result = "RecoveredVector<" +
                        std::to_string(vo->size) + ">{}";
                    const int lanes =
                        std::max(1, vo->size / laneBytes);
                    for (int lane = lanes - 1; lane >= 0; --lane) {
                        std::string lv, rv;
                        if (vectorSource) {
                            lv = "recovered_vector_extract<" + laneType +
                                 ">(" + lText + ", " +
                                 std::to_string(lane) + ")";
                            rv = "recovered_vector_extract<" + laneType +
                                 ">(" + rText + ", " +
                                 std::to_string(lane) + ")";
                        } else {
                            const unsigned shift = lane * laneBits;
                            const std::string mask =
                                laneBits >= 64
                                    ? "~0ULL"
                                    : "((1ULL << " +
                                          std::to_string(laneBits) +
                                          ") - 1)";
                            const unsigned sourceBits =
                                static_cast<unsigned>(lhsNode ? lhsNode->size : 8) * 8;
                            if (shift >= sourceBits) {
                                lv = zeroLane;
                                rv = zeroLane;
                            } else {
                                lv = "(" + laneType + ")((" + lText +
                                     ") >> " + std::to_string(shift) +
                                     " & " + mask + ")";
                                rv = "(" + laneType + ")((" + rText +
                                     ") >> " + std::to_string(shift) +
                                     " & " + mask + ")";
                            }
                        }
                        std::string predicate;
                        if (greater) {
                            predicate = signedCompare
                                ? "((int64_t)(" + lv + ") > (int64_t)(" +
                                      rv + "))"
                                : "((" + lv + ") > (" + rv + "))";
                        } else {
                            predicate = "((" + lv + ") == (" + rv +
                                         "))";
                        }
                        result = "recovered_vector_insert<" + laneType +
                                 ">(" + result + ", " + predicate +
                                 " ? " + onesLane + " : " + zeroLane +
                                 ", " + std::to_string(lane) + ")";
                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_STRING_COMPARE: {
                    const CExpr left = exprOfV(pi.find(op.in0));
                    const CExpr right = exprOfV(pi.find(op.in1));
                    const CExpr lengths = op.in2
                        ? exprOfV(pi.find(op.in2))
                        : CExpr{"0", 8, true};
                    r.text = "recovered_simd_string_compare(" +
                        stripParens(left.text) + ", " +
                        stripParens(right.text) + ", " +
                        stripParens(lengths.text) + ", " +
                        std::to_string(op.aux) + ")";
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_MOVEMASK: {
                    // vpmovmskb/pmovmskb/movmskps/movmskpd: the most
                    // significant bit of each source lane becomes one bit
                    // of the integer result.  aux = laneBits.
                    const CExpr source = exprOfV(pi.find(op.in0));
                    const Varnode* sourceNode = pi.find(op.in0);
                    const unsigned laneBits =
                        (op.aux & 0xffU) ? (op.aux & 0xffU) : 8;
                    const int laneBytes = static_cast<int>(laneBits / 8);
                    const bool vectorSource =
                        sourceNode && sourceNode->size > 8;
                    const std::string sText = stripParens(source.text);
                    std::string result = "0";                    // The mask width is driven by the source vector lane
                    // count (vpmovmskb ymm -> 32 bits), capped by the
                    // destination register width so the emitted expression
                    // stays representable in vo->size bytes.
                    const int sourceLanes = vectorSource
                        ? static_cast<int>(sourceNode->size / laneBytes)
                        : static_cast<int>(vo->size * 8 /
                                           static_cast<int>(laneBits));
                    const int lanes = std::min(
                        sourceLanes, vo->size * 8 / static_cast<int>(laneBits));
                    for (int lane = 0; lane < lanes; ++lane) {
                        std::string laneValue;
                        if (vectorSource) {
                            laneValue = "recovered_vector_extract<" +
                                std::string(uCast(laneBytes)) + ">(" + sText +
                                ", " + std::to_string(lane) + ")";
                        } else {
                            const unsigned shift = lane * laneBits;
                            const unsigned sourceBits =
                                static_cast<unsigned>(sourceNode ? sourceNode->size : 8) * 8;
                            if (shift >= sourceBits) {
                                laneValue = "(" + std::string(uCast(laneBytes)) +
                                            ")0";
                            } else {
                                laneValue = "(" + std::string(uCast(laneBytes)) +
                                    ")((" + sText + ") >> " +
                                    std::to_string(shift) + ")";
                            }
                        }
                        result = "(" + result + " | " +
                            "(((" + laneValue + ") >> " +
                            std::to_string(laneBits - 1) + ") & 1U) << " +
                            std::to_string(lane) + ")";                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_EXTEND: {
                    // pmovsx/pmovzx: lane-wise sign/zero extension from
                    // sourceBits lanes to destinationBits lanes.  aux =
                    // sourceBits | (destinationBits << 8) | (signed << 15).
                    // The source lane count is derived from the destination
                    // vector width; lanes beyond the source are zero.
                    const CExpr source = exprOfV(pi.find(op.in0));
                    const Varnode* sourceNode = pi.find(op.in0);
                    const int sourceBits =
                        (op.aux & 0xff) ? (op.aux & 0xff) : 8;
                    const int destinationBits =
                        ((op.aux >> 8) & 0x7f) ? ((op.aux >> 8) & 0x7f) : 16;
                    const bool signedExtend = (op.aux & 0x8000) != 0;
                    const int destinationBytes = destinationBits / 8;
                    const int lanes =
                        std::max(1, vo->size / destinationBytes);
                    const std::string sourceType =
                        sourceBits == 8 ? "int8_t"
                        : sourceBits == 16 ? "int16_t"
                        : sourceBits == 32 ? "int32_t" : "int64_t";
                    const std::string destinationType =
                        destinationBits == 16 ? "int16_t"
                        : destinationBits == 32 ? "int32_t"
                        : destinationBits == 64 ? "int64_t" : "int32_t";
                    const bool vectorSource =
                        sourceNode && sourceNode->size > 8;
                    const std::string sText = stripParens(source.text);
                    std::string result = "RecoveredVector<" +
                        std::to_string(vo->size) + ">{}";
                    for (int lane = lanes - 1; lane >= 0; --lane) {
                        std::string laneValue;
                        if (vectorSource) {
                            laneValue = "recovered_vector_extract<" +
                                sourceType + ">(" + sText + ", " +
                                std::to_string(lane) + ")";
                        } else {
                            const unsigned shift = lane * sourceBits;
                            laneValue = "(" + sourceType + ")((" + sText +
                                ") >> " + std::to_string(shift) + ")";
                        }
                        std::string extended =
                            signedExtend
                                ? "(" + destinationType + ")(int64_t)(" +
                                      laneValue + ")"
                                : "(" + destinationType + ")(uint64_t)(" +
                                      laneValue + ") & " +
                                      std::to_string(
                                          destinationBits == 64
                                              ? ~0ULL : (1ULL << destinationBits) - 1);
                        result = "recovered_vector_insert<" +
                            destinationType + ">(" + result + ", " +
                            extended + ", " + std::to_string(lane) + ")";
                    }
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SIMD_ZERO_UPPER: {
                    // vzeroupper: zero the upper 128 bits of each YMM/ZMM
                    // register, leaving the low XMM half intact.  The
                    // project C model carries the full RecoveredVector byte
                    // array, so clear every byte from offset 16 up.
                    const CExpr vector = exprOfV(pi.find(op.in0));
                    const std::string v = stripParens(vector.text);
                    std::string result = v;
                    for (int lane = 16; lane < vo->size; ++lane)
                        result = "recovered_vector_insert<uint8_t>(" +
                                 result + ", (uint8_t)0, " +
                                 std::to_string(lane) + ")";
                    r.text = result;
                    r.size = vo->size;
                    break;
                }
                case POp::SELECT: {
                    const CExpr c = exprOfV(pi.find(op.in0));
                    const CExpr yes = exprOfV(pi.find(op.in1));
                    const CExpr no = exprOfV(pi.find(op.in2));
                    r.text = "(" + stripParens(c.text) + " ? " +
                             stripParens(yes.text) + " : " + stripParens(no.text) + ")";
                    r.size = vo->size;
                    break;
                }
                case POp::LOAD: {
                    int64_t slot = 0;
                    if (slotOf(pi, op.in0, slot)) {
                        // Phase 10f: restore a confirmed pop slot from its
                        // saved_<slot> variable; flush drops the paired rsp
                        // write.
                        int64_t piDelta = 0;
                        if (!useRecoveredRuntime && pushSlots &&
                            piRspDelta(pi, architecture, piDelta) &&
                            piDelta == 8) {
                            const auto saved = pushSlots->find(slot);
                            if (saved != pushSlots->end()) {
                                r = CExpr{saved->second.savedName, vo->size,
                                          false};
                                dropRspWrite = true;
                                break;
                            }
                        }
                        const StackSlot* ss =
                            stackModel ? stackModel->slotAt(slot) : nullptr;
                        if (ss && ss->promoted) {
                            r = CExpr{ss->variableName, vo->size, false};
                        } else if (!useRecoveredRuntime) {
                            r = CExpr{localName(slot), vo->size, false};
                        } else {
                            const CExpr a = exprOfV(pi.find(op.in0));
                            r.text =
                                "recovered_load<" + std::string(uCast(vo->size)) +
                                ">(" + stripParens(a.text) + ")";
                            r.size = vo->size;
                            r.ctype = uCast(vo->size);
                        }
                    } else if (!useRecoveredRuntime && globals) {
                        // Phase 8: name constant-address data accesses.
                        const Varnode* addrNode = pi.find(op.in0);
                        if (addrNode && addrNode->kind == Varnode::CONST) {
                            const GlobalObject* object =
                                globals->objectAt(addrNode->offset);
                            if (object) {
                                r.text =
                                    "(*(" + std::string(uCast(vo->size)) +
                                    " *)(uintptr_t)(" + object->name + "))";
                                r.size = vo->size;
                                r.ctype = uCast(vo->size);
                                break;
                            }
                            // Phase 10h: accesses inside an object's span
                            // (g_data_xxx + 1) still name the object.
                            uint64_t offset = 0;
                            object = globals->objectContaining(
                                addrNode->offset, offset);
                            if (object && offset != 0) {
                                r.text =
                                    "(*(" + std::string(uCast(vo->size)) +
                                    " *)(uintptr_t)(" + object->name + " + " +
                                    std::to_string(offset) + "))";
                                r.size = vo->size;
                                r.ctype = uCast(vo->size);
                                break;
                            }
                        }
                        const CExpr a = exprOfV(pi.find(op.in0));
                        r.text = "(*(" + std::string(uCast(vo->size)) +
                                  " *)(" + stripParens(a.text) + "))";
                        r.size = vo->size;
                        r.ctype = uCast(vo->size);
                    } else {
                        const CExpr a = exprOfV(pi.find(op.in0));
                        r.text = useRecoveredRuntime
                            ? "recovered_load<" + std::string(uCast(vo->size)) +
                                  ">(" + stripParens(a.text) + ")"
                            : "(*(" + std::string(uCast(vo->size)) +
                                  " *)(" + stripParens(a.text) + "))";
                        r.size = vo->size;
                        r.ctype = uCast(vo->size);
                    }
                    break;
                }
                default:
                    r.text = "0 /* unknown */";
                    r.size = vo->size;
                    break;
                }
                // Propagate register dependencies through UNIQUE expression
                // trees.  Text alone is insufficient here: an instruction
                // can write one architectural result before another result's
                // generated C expression has been evaluated.
                for (uint64_t input : {op.in0, op.in1, op.in2}) {
                    const CExpr inputExpression = exprOfV(pi.find(input));
                    r.readsMemory = r.readsMemory || inputExpression.readsMemory;
                    for (const auto& reference : inputExpression.registerRefs)
                        r.registerRefs[reference.first].insert(
                            reference.second.begin(), reference.second.end());
                }
                if (op.op == POp::LOAD) r.readsMemory = true;
                if (op.op == POp::LOAD && std::any_of(
                        pi.ops.begin(), pi.ops.end(), [](const PcodeOp& other) {
                            return other.op == POp::STORE;
                        })) {
                    // UNIQUE expressions are usually deferred until their
                    // consumer. A read-modify-write instruction must instead
                    // capture the old memory value before emitting STORE
                    // (XCHG/XADD/CMPXCHG may return that old value afterwards).
                    const std::string snapshot = "recovered_memory_" +
                        std::to_string(pi.addr) + "_" + std::to_string(op.out);
                    line("const auto " + snapshot + " = " + r.text + ";");
                    r.text = snapshot;
                    r.readsMemory = false;
                    r.registerRefs.clear();
                    r.isConst = false;
                }
                // The destination varnode, not the right-hand expression,
                // defines the architectural write width.  In particular,
                // COPY of an untyped integer constant into AL/AH/EAX must not
                // silently become a full-width RAX assignment.
                r.size = vo->size;
                if (vo->kind == Varnode::REGISTER) {
                    if (architecture.rfind("riscv", 0) != 0 || vo->offset != 0)
                        pending.emplace_back(vo->offset, r);
                } else {
                    temps[vo] = r;
                }
            }
            std::map<uint64_t, size_t> firstWrite;
            for (size_t index = 0; index < pending.size(); ++index) {
                const uint64_t storage = registerStorageOffset(
                    architecture, pending[index].first,
                    pending[index].second.size);
                firstWrite.emplace(storage, index);
            }

            std::map<std::string, std::string> snapshots;
            for (size_t index = 0; index < pending.size(); ++index) {
                for (const auto& reference : pending[index].second.registerRefs) {
                    const auto write = firstWrite.find(reference.first);
                    if (write == firstWrite.end() || write->second >= index)
                        continue;
                    for (const std::string& name : reference.second) {
                        snapshots.emplace(
                            name, "recovered_old_" + std::to_string(pi.addr) +
                                      "_" + safeIdentifier(name));
                    }
                }
            }
            if (dropRspWrite)
                snapshots.erase("rsp"); // folded rsp write: no old value needed
            if (!snapshots.empty()) {
                line("{");
                ++indent;
                for (const auto& snapshot : snapshots)
                    line("const auto " + snapshot.second + " = " +
                         snapshot.first + ";");
            }

        // Phase 10b-2: track block-local register definitions for argument
        // inlining, invalidating any entry whose expression reads a register
        // that this instruction redefines.
        for (const auto& write : pending) {
            const uint64_t written = registerStorageOffset(
                architecture, write.first, write.second.size);
            if (entryBlock && paramIndex.count(written))
                paramDefined.insert(written);
            if (liveFlags && written >= 4096 && written <= 4101 &&
                !liveFlags->count(written))
                continue; // Phase 10g: dead flag write
            const bool foldedSpWrite =
                dropRspWrite &&
                written == stackPointerOffset(architecture) &&
                write.second.size == 8;
            for (auto it = regExpr.begin(); it != regExpr.end();) {
                bool depends = false;
                for (const auto& ref : it->second.registerRefs)
                    if (ref.first == written) { depends = true; break; }
                if (depends)
                    it = regExpr.erase(it);
                else
                    ++it;
            }
            if (foldedSpWrite) {
                // The output rsp does not change, so no stale definition may
                // be inlined as if the adjustment had been emitted.
                regExpr.erase(written);
                continue;
            }
            if (write.second.registerRefs.count(written)) {
                // Self-referential definition (rcx = rcx + K, rcx = rcx ^ rcx):
                // the C variable is updated once at this statement, so inlining
                // the recorded expression at a later call site would re-apply
                // the operation on top of the already-updated value.  Keep the
                // plain register name (runtime value) instead of the text.
                regExpr.erase(written);
                continue;
            }
            uint64_t sliceBase = 0;
            unsigned sliceShift = 0;
            if (x86GprSlice(architecture, write.first, write.second.size,
                            sliceBase, sliceShift)) {
                if (write.second.size < 4) {
                    // AL/AH/AX writes preserve the other bits of the GPR.
                    // Their RHS is not a definition of the complete RAX.
                    regExpr.erase(written);
                    continue;
                }
                if (write.second.size == 4) {
                    CExpr extended = write.second;
                    extended.text = "(uint32_t)(" + extended.text + ")";
                    extended.size = 8;
                    regExpr[written] = std::move(extended);
                    continue;
                }
            }
            regExpr[written] = write.second;
        }
        for (const auto& kv : pending) {
                const uint64_t storage = registerStorageOffset(
                    architecture, kv.first, kv.second.size);
                if (liveFlags && storage >= 4096 && storage <= 4101 &&
                    !liveFlags->count(storage))
                    continue; // Phase 10g: dead flag write
                // track sp adjustment (prologue/frame): sp = sp +/- K
                const bool isSpWrite =
                    storage == stackPointerOffset(architecture) &&
                    kv.second.size == 8;
                int64_t spDelta = 0;
                const bool spDeltaKnown =
                    isSpWrite &&
                    parseSpExpr(kv.second.text,
                                registerName(architecture, storage, 8),
                                spDelta);
                const bool foldSpWrite =
                    dropRspWrite && isSpWrite && spDeltaKnown;
                bool emittedSpWrite = false;
                if (isSpWrite && !foldSpWrite) {
                    if (spDeltaKnown) spBias += spDelta;
                    // rebaseText must still see the current rebase when the
                    // write line is emitted below; only then is the output
                    // variable back on the simulated frame.
                    emittedSpWrite = true;
                } else if (foldSpWrite) {
                    // Folded push/pop: the simulated frame still moves but
                    // the output variable does not, so offset the rebase.
                    spBias += spDelta;
                    rspRebase -= spDelta;
                    continue;
                }
                // Phase 10e: drop dead register writes - no real reads in
                // any successor or later in this block, side-effect-free
                // expression, and not the return register (retValue may
                // still need it).  ABI call-argument registers only block
                // elimination of non-constant definitions: constant argument
                // setups are always inlined into the call text by 10b-2.
                if (!isSpWrite && liveOut && !liveOut->count(storage) &&
                    !readAfter(storage, piIndex) &&
                    storage != registerStorageOffset(
                                   architecture,
                                   returnRegisterOffset(architecture), 8) &&
                    inlineableExpression(kv.second) &&
                    (!liveOutCall || !liveOutCall->count(storage) ||
                     (callArgsLocal && callArgsLocal->count(storage) &&
                      kv.second.isConst)))
                    continue;
                // track constant-valued registers (for jalr resolution)
                {
                    int64_t k = 0;
                    std::string reg;
                    if (parseRegConstExpr(kv.second.text, reg, k) &&
                        reg.empty()) {
                        uint64_t base = kv.first;
                        unsigned shift = 0;
                        const bool x86Slice = x86GprSlice(
                            architecture, kv.first, kv.second.size, base,
                            shift);
                        // x86: only full-width/32-bit GPR writes enter the
                        // constant table.  Wide or non-GPR targets (XMM,
                        // flags, memory temps) must erase instead: x86
                        // aliases XMM0's storage offset with RAX, so
                        // recording "xmm0 = 0" there would poison a later
                        // indirect-call target resolution (CALL [RAX+0x70]
                        // folding RAX to 0 and yielding FUN_70).
                        // Non-x86 keeps the original broad rule so RISC-V
                        // auipc+jalr constant tracking still works.
                        const bool gprConstantWrite =
                            architecture.rfind("x86", 0) == 0
                                ? (x86Slice &&
                                   (kv.second.size == 8 ||
                                    (kv.second.size == 4 && shift == 0)))
                                : true;
                        if (gprConstantWrite) {
                            if (kv.second.size == 4)
                                k = static_cast<uint32_t>(k);
                            regConst[storage] = k;
                        } else {
                            regConst.erase(storage);
                        }
                    } else {
                        regConst.erase(storage);
                    }
                }
                std::string expression = kv.second.text;
                for (const auto& snapshot : snapshots)
                    expression = replaceIdentifier(expression, snapshot.first,
                                                   snapshot.second);
                if (emittedSpWrite) {
                    // rsp write: re-base only the right-hand side so the
                    // output variable lands on the simulated frame; the LHS
                    // register name must stay a plain identifier.
                    lineRaw(x86RegisterWrite(architecture, kv.first,
                                             kv.second.size,
                                             rebaseText(stripParens(expression))) +
                            ";");
                    rspRebase = 0; // output re-synced
                } else {
                    line(x86RegisterWrite(architecture, kv.first,
                                          kv.second.size,
                                          stripParens(expression)) +
                         ";");
                }
            }
            if (!snapshots.empty()) {
                --indent;
                line("}");
            }
            pending.clear();
        }
    }

    std::string retValue() const {
        const uint64_t offset = returnRegisterOffset(architecture);
        // Phase 10c: inline a block-local, side-effect-free definition of
        // the return register (rax = rsp + 40; return rax -> return rsp+40).
        // Call results are kept as the register name by inlineableExpression.
        const uint64_t storage =
            registerStorageOffset(architecture, offset, 8);
        const auto definition = regExpr.find(storage);
        if (definition != regExpr.end() &&
            inlineableExpression(definition->second))
            return rebaseText(stripParens(definition->second.text));
        return rebaseText(registerName(architecture, offset));
    }

    // Phase 10f: re-base rsp references when folded push/pop adjustments
    // left the output rsp variable offset from the simulated frame.
    std::string rebaseText(const std::string& s) const {
        return rspRebase ? rebaseRspText(s, rspRebase) : s;
    }

    // Phase 10h: recover a printable, NUL-terminated C string at `address`
    // (4..256 bytes, non-executable data) as a C string literal; "" when
    // the target is not a string (code, binary data, or unreadable).
    std::string stringLiteralAt(uint64_t address) const {
        if (!memRead || address < 0x10000ULL) return "";
        unsigned char buffer[257];
        if (!memRead(address, buffer, sizeof(buffer))) return "";
        size_t length = 0;
        while (length < sizeof(buffer) && buffer[length] != 0) {
            if (buffer[length] < 0x20 || buffer[length] > 0x7e) return "";
            ++length;
        }
        if (length == sizeof(buffer) || length < 4) return "";
        std::string literal = "\"";
        for (size_t index = 0; index < length; ++index) {
            const char c = static_cast<char>(buffer[index]);
            if (c == '"' || c == '\\') literal += '\\';
            literal += c;
        }
        literal += "\"";
        return literal;
    }

    // Phase 10e: is this register read at or after the given instruction
    // position within the current block?
    bool readAfter(uint64_t storage, size_t piIndex) const {
        if (!readPos) return true; // unknown -> keep the write
        const auto it = readPos->find(storage);
        if (it == readPos->end()) return false;
        for (const int position : it->second)
            if (static_cast<size_t>(position) >= piIndex) return true;
        return false;
    }

private:
    const CfgBlock& blk_;
    // Phase: stack argument slots written before a CALLIND.  x64 passes the
    // 5th+ argument on the caller's stack at rsp+0x20..0x38; recovered code
    // simulates those writes with recovered_store(rsp + K, ...) which the
    // callee never sees (simulated stack != hardware stack).  Record the
    // values and forward them as dispatch arguments a4..a7 instead of 0s.
    std::map<int64_t, std::string> callArgSlots_;
    void lineRaw(const std::string& s) {
        for (int i = 0; i < indent; ++i) out << "    ";
        out << s << "\n";
    }
    void line(const std::string& s) {
        lineRaw(rebaseText(s));
    }
};

} // namespace

std::string decompile(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end,
    const std::function<std::string(uint64_t)>& nameOf,
    const std::function<std::optional<FunctionSignature>(uint64_t)>& signatureOf,
    const std::string& architecture, bool useRecoveredRuntime,
    const StackFrameModel* stackModel,
    const GlobalObjectRecovery* globals,
    const std::function<bool(uint64_t)>& guardSlotOf,
    const std::string& entryName) {
    CfgBuilder cfg;
    if (!cfg.build(eng, read, start, end)) return "// failed to build CFG\n";

    std::ostringstream out;
    out << "// decompiled " << hexAddr(start) << "\n";

    std::set<uint64_t> labeled;
    for (const auto& b : cfg.blocks())
        labeled.insert(b.start); // incl. start: loops jump back to the header

    // Phase 10g: collect x86 flag registers (r4096..r4101) that are read
    // anywhere in the function, so dead flag writes can be dropped.
    std::set<uint64_t> liveFlags;
    if (architecture.rfind("x86", 0) == 0) {
        for (const auto& b : cfg.blocks())
            for (const auto& pi : b.insns)
                for (const auto& op : pi.ops) {
                    const uint64_t operands[3] = {op.in0, op.in1, op.in2};
                    for (const uint64_t operand : operands) {
                        const Varnode* v = pi.find(operand);
                        if (v && v->kind == Varnode::REGISTER &&
                            v->offset >= 4096 && v->offset <= 4101)
                            liveFlags.insert(v->offset);
                    }
                }
    }

    // Phase 10f (native view): find push/pop save slots.  A slot is a pure
    // callee-save spill when it is written exactly once by a push-like
    // instruction (rsp - 8) and restored exactly once by a pop-like
    // instruction (rsp + 8) into the same register.  Such slots are emitted
    // as saved_<slot> variables with their rsp adjustments folded away,
    // leaving the simulated rsp only for the real frame allocation.
    std::map<int64_t, PushSlotInfo> pushSlots;
    if (!useRecoveredRuntime && architecture.rfind("x86", 0) == 0) {
        // Entry bias per block: the most negative predecessor exit bias,
        // mirroring how frameBias propagates through block emission.
        std::map<uint64_t, int64_t> entryBias;
        entryBias[start] = 0;
        for (int pass = 0; pass < 16; ++pass) {
            bool changed = false;
            for (const auto& b : cfg.blocks()) {
                if (b.start == start) continue;
                int64_t bias = std::numeric_limits<int64_t>::max();
                for (const uint64_t pred : cfg.predecessors(b.start)) {
                    const auto it = entryBias.find(pred);
                    if (it == entryBias.end()) continue;
                    const CfgBlock* pb = cfg.blockAt(pred);
                    if (!pb) continue;
                    bias = std::min(bias, simulateBlockSp(*pb, it->second,
                                                         architecture));
                }
                if (bias != std::numeric_limits<int64_t>::max()) {
                    const auto cur = entryBias.find(b.start);
                    if (cur == entryBias.end() || cur->second != bias) {
                        entryBias[b.start] = bias;
                        changed = true;
                    }
                }
            }
            if (!changed) break;
        }
        std::map<int64_t, int> storeCount, loadCount;
        std::map<int64_t, std::string> storedReg, loadedReg;
        std::map<int64_t, int64_t> storeDelta, loadDelta;
        for (const auto& b : cfg.blocks()) {
            const auto eit = entryBias.find(b.start);
            if (eit == entryBias.end()) continue;
            int64_t bias = eit->second;
            BlockEmitter probe(b);
            probe.spBias = bias;
            probe.architecture = architecture;
            probe.stackModel = stackModel;
            for (const auto& pi : b.insns) {
                int64_t piDelta = 0;
                const bool hasDelta = piRspDelta(pi, architecture, piDelta);
                probe.spBias = bias; // slot addresses use the pre-instruction bias
                for (const auto& op : pi.ops) {
                    int64_t slot = 0;
                    if (op.op == POp::STORE && probe.slotOf(pi, op.in0, slot) &&
                        slot < 0) {
                        storeCount[slot]++;
                        storeDelta[slot] = hasDelta ? piDelta : 0;
                        const Varnode* vs = pi.find(op.in2);
                        if (vs && vs->kind == Varnode::REGISTER &&
                            vs->size == 8 &&
                            registerStorageOffset(architecture, vs->offset,
                                                  vs->size) !=
                                stackPointerOffset(architecture))
                            storedReg[slot] = registerName(
                                architecture,
                                registerStorageOffset(architecture, vs->offset,
                                                      vs->size));
                        else
                            storedReg[slot].clear();
                    } else if (op.op == POp::LOAD &&
                               probe.slotOf(pi, op.in0, slot) && slot < 0) {
                        loadCount[slot]++;
                        loadDelta[slot] = hasDelta ? piDelta : 0;
                        // pop: LOAD u3, rsp; ...; COPY rbx, u3 - the
                        // destination register is the later COPY's target.
                        const Varnode* vo = pi.find(op.out);
                        std::string reg;
                        if (vo && vo->kind == Varnode::REGISTER &&
                            vo->size == 8) {
                            reg = registerName(
                                architecture,
                                registerStorageOffset(architecture,
                                                      vo->offset, vo->size));
                        } else if (vo && vo->kind == Varnode::UNIQUE) {
                            for (const auto& op2 : pi.ops) {
                                if (op2.op != POp::COPY || op2.in0 != vo->id)
                                    continue;
                                const Varnode* dest = pi.find(op2.out);
                                if (dest && dest->kind == Varnode::REGISTER &&
                                    dest->size == 8)
                                    reg = registerName(
                                        architecture,
                                        registerStorageOffset(
                                            architecture, dest->offset,
                                            dest->size));
                                break;
                            }
                        }
                        loadedReg[slot] = reg;
                    }
                }
                if (hasDelta) bias += piDelta;
            }
        }
        for (const auto& kv : storeCount) {
            const int64_t slot = kv.first;
            if (kv.second != 1 || loadCount[slot] != 1 ||
                storeDelta[slot] != -8 || loadDelta[slot] != 8 ||
                storedReg[slot].empty() || storedReg[slot] != loadedReg[slot])
                continue;
            PushSlotInfo info;
            info.savedName = "saved_m" + std::to_string(-slot);
            info.storedReg = storedReg[slot];
            info.storeDelta = -8;
            info.loadDelta = 8;
            pushSlots[slot] = info;
        }
    }

    // Phase 10e (native view): block-level register liveness for dead
    // register-write elimination.  liveOut[b] = registers read in any
    // successor reachable without an intervening write; liveOutCall[b] also
    // carries ABI call-argument registers.  Within a block, instruction-level
    // read positions (blockReadPos) decide whether a write is followed by a
    // real read.
    std::map<uint64_t, std::set<uint64_t>> liveOut, liveOutCall;
    std::map<uint64_t, std::set<uint64_t>> callArgsLocal;
    std::map<uint64_t, std::map<uint64_t, std::vector<int>>> blockReadPos;
    const bool livenessEnabled =
        !useRecoveredRuntime && architecture.rfind("x86", 0) == 0;
    if (livenessEnabled) {
        for (const auto& b : cfg.blocks()) { // seed entries for every block
            liveOut[b.start];
            liveOutCall[b.start];
            callArgsLocal[b.start];
            blockReadPos[b.start];
        }
    }
    auto findLiveSet = [](const std::map<uint64_t, std::set<uint64_t>>& m,
                          uint64_t key) -> const std::set<uint64_t>* {
        const auto it = m.find(key);
        return it == m.end() ? nullptr : &it->second;
    };
    auto findReadPos =
        [](const std::map<uint64_t,
                         std::map<uint64_t, std::vector<int>>>& m,
           uint64_t key) -> const std::map<uint64_t, std::vector<int>>* {
        const auto it = m.find(key);
        return it == m.end() ? nullptr : &it->second;
    };
    if (!useRecoveredRuntime && architecture.rfind("x86", 0) == 0) {
        const std::vector<uint64_t> abiRegs =
            defaultArgumentRegisters(architecture);
        std::map<uint64_t, std::set<uint64_t>> readIn, writtenIn,
            callReadIn;
        for (const auto& b : cfg.blocks()) {
            const size_t piCount = b.insns.size();
            for (size_t piIndex = 0; piIndex < piCount; ++piIndex) {
                const auto& pi = b.insns[piIndex];
                for (const auto& op : pi.ops) {
                    const Varnode* out = pi.find(op.out);
                    if (out && out->kind == Varnode::REGISTER)
                        writtenIn[b.start].insert(
                            registerStorageOffset(architecture, out->offset,
                                                  out->size));
                    if (op.op == POp::CALL || op.op == POp::CALLIND) {
                        // ABI argument registers may be consumed by name at
                        // the call site; the target operand is still a real
                        // read (indirect calls), so fall through.
                        for (const uint64_t reg : abiRegs)
                            callReadIn[b.start].insert(reg);
                    }
                    std::set<uint64_t> refs;
                    collectRegRefs(pi, op.in0, architecture, refs);
                    collectRegRefs(pi, op.in1, architecture, refs);
                    collectRegRefs(pi, op.in2, architecture, refs);
                    if (op.op == POp::X86_STRING) {
                        // rep movs/stos/lods/scas use rcx/rsi/rdi/rax
                        // implicitly in the emitted C.
                        for (const uint64_t reg : {8ULL, 48ULL, 56ULL, 0ULL})
                            refs.insert(reg);
                    }
                    for (const uint64_t r : refs) {
                        readIn[b.start].insert(r);
                        blockReadPos[b.start][r].push_back(
                            static_cast<int>(piIndex));
                    }
                }
            }
            if (b.tailCallTarget) {
                // tail calls consume the ABI argument registers by name
                for (const uint64_t reg : abiRegs) {
                    readIn[b.start].insert(reg);
                    blockReadPos[b.start][reg].push_back(
                        static_cast<int>(piCount));
                }
            }
        }
        callArgsLocal = callReadIn;
        std::map<uint64_t, std::set<uint64_t>> fullIn = readIn;
        for (const auto& kv : callReadIn)
            for (const uint64_t r : kv.second)
                fullIn[kv.first].insert(r);
        for (int pass = 0; pass < 32; ++pass) {
            bool changed = false;
            for (const auto& b : cfg.blocks()) {
                for (auto* out : {&liveOut, &liveOutCall}) {
                    auto& cur = (*out)[b.start];
                    std::set<uint64_t> merged = cur;
                    for (const uint64_t successor : b.succs) {
                        const auto& succIn = (out == &liveOut)
                            ? fullIn : readIn;
                        const auto it = succIn.find(successor);
                        if (it != succIn.end())
                            for (const uint64_t r : it->second)
                                if (!writtenIn[b.start].count(r))
                                    merged.insert(r);
                        const auto it2 = out->find(successor);
                        if (it2 != out->end())
                            for (const uint64_t r : it2->second)
                                if (!writtenIn[b.start].count(r))
                                    merged.insert(r);
                    }
                    if (merged.size() != cur.size()) {
                        cur = merged;
                        changed = true;
                    }
                }
            }
            if (!changed) break;
        }
    }

    std::set<uint64_t> emitted;
    int64_t frameBias = 0; // sp bias right after the prologue (for locals)
    std::optional<uint64_t> suppressBackedgeTo; // structured loop backedge

    // Readability: when the caller knows the function's symbol, name the
    // entry block after it instead of a raw address label.  All other
    // blocks are named by their offset from the function start (short and
    // stable), falling back to a full address label if a stray target lies
    // before `start`.  References and definitions share this helper so
    // they can never disagree; the missing-label safety net below parses
    // tokens back through the same function.
    auto labelName = [&](uint64_t a) {
        if (a == start && !entryName.empty())
            return safeIdentifier(entryName);
        if (a >= start) {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "L0x%llx",
                          static_cast<unsigned long long>(a - start));
            return std::string(buf);
        }
        return "L" + hexAddr(a);
    };

    std::function<void(uint64_t, int)> emitBlock;
    std::set<uint64_t> danglingLabels;
    emitBlock = [&](uint64_t a, int depth) {
        if (emitted.count(a)) {
            for (int i = 0; i < depth; ++i) out << "    ";
            out << "goto " << labelName(a) << ";\n";
            return;
        }
        emitted.insert(a);
        const CfgBlock* b = cfg.blockAt(a);
        if (!b) {
            if (labeled.count(a)) {
                for (int i = 0; i < depth; ++i) out << "    ";
                out << labelName(a) << ":;\n";
            }
            return;
        }
        if (labeled.count(a)) {
            for (int i = 0; i < depth; ++i) out << "    ";
            out << labelName(a) << ":\n";
        }

        const NaturalLoop* loop = cfg.loopByHeader(a);
        if (loop && loop->blocks.size() == 1) {
            const PcodeInsn* term = b->terminator();
            if (term && term->kind == Insn::JCC && b->succs.size() == 2 &&
                loop->exits.size() == 1) {
                const bool targetRepeats = term->targetKnown && term->target == a;
                const bool fallRepeats = b->succs[0] == a;
                if (targetRepeats || fallRepeats) {
                    BlockEmitter body(*b);
                    body.indent = depth + 2;
                    body.nameOf = nameOf;
                    body.guardSlotOf = guardSlotOf;
                    body.signatureOf = signatureOf;
                    body.architecture = architecture;
                    body.useRecoveredRuntime = useRecoveredRuntime;
                    body.stackModel = stackModel;
    body.globals = globals;

                    body.spBias = frameBias;

                    body.entryBlock = !useRecoveredRuntime && (a == start);
body.liveFlags = &liveFlags;
body.liveOut = livenessEnabled ? findLiveSet(liveOut, b->start) : nullptr;
body.liveOutCall = livenessEnabled ? findLiveSet(liveOutCall, b->start) : nullptr;
body.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
body.readPos = livenessEnabled ? findReadPos(blockReadPos, b->start) : nullptr;
body.memRead = read;


body.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
body.pushSlots = &pushSlots;
                    body.emit();
                    if (body.hasCond && !body.cond.empty()) {
                        for (int i = 0; i <= depth; ++i) out << "    ";
                        out << "do {\n" << body.out.str();
                        for (int i = 0; i <= depth; ++i) out << "    ";
                        const std::string condition =
                            targetRepeats ? body.cond
                                          : "!(" + body.cond + ")";
                        out << "} while (" << condition << ");\n";
                        frameBias = std::min(frameBias, body.spBias);
                        emitBlock(loop->exits.front().second, depth);
                        return;
                    }
                }
            }
            if (term && term->kind == Insn::JMP && term->targetKnown &&
                term->target == a && loop->exits.empty()) {
                BlockEmitter body(*b);
                body.indent = depth + 2;
                body.nameOf = nameOf;
                    body.guardSlotOf = guardSlotOf;
                body.signatureOf = signatureOf;
                body.architecture = architecture;
                body.useRecoveredRuntime = useRecoveredRuntime;
                    body.stackModel = stackModel;
    body.globals = globals;

                body.spBias = frameBias;

                body.entryBlock = !useRecoveredRuntime && (a == start);
body.liveFlags = &liveFlags;
body.liveOut = livenessEnabled ? findLiveSet(liveOut, b->start) : nullptr;
body.liveOutCall = livenessEnabled ? findLiveSet(liveOutCall, b->start) : nullptr;
body.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
body.readPos = livenessEnabled ? findReadPos(blockReadPos, b->start) : nullptr;
body.memRead = read;


body.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
body.pushSlots = &pushSlots;
                body.emit();
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "while (1) {\n" << body.out.str();
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "}\n";
                frameBias = std::min(frameBias, body.spBias);
                return;
            }
        }

        // Conservative canonical while: a condition-only header, a
        // straight-line body chain (one or more blocks) ending in an
        // unconditional back edge to the header, one exit.
        if (loop && loop->blocks.size() >= 2 && loop->exits.size() == 1 &&
            loop->backEdges.size() == 1) {
            uint64_t bodyAddr = 0;
            for (uint64_t member : loop->blocks)
                if (member != a) bodyAddr = member;
            const CfgBlock* bodyBlock = cfg.blockAt(bodyAddr);
            const PcodeInsn* headerTerm = b->terminator();
            if (bodyBlock && !cfg.loopByHeader(bodyAddr) && headerTerm &&
                headerTerm->kind == Insn::JCC && b->succs.size() == 2) {
                bool bodyInLoop = false, exitInLoop = false;
                for (uint64_t s : b->succs) {
                    bodyInLoop |= loop->blocks.count(s) != 0;
                    exitInLoop |= !loop->blocks.count(s);
                }
                if (bodyInLoop && exitInLoop) {
                    // Build the straight-line body chain (all members in the
                    // loop, no internal conditionals, no nested loops) ending
                    // with a JMP back to the header.
                    std::vector<uint64_t> chain;
                    std::set<uint64_t> chainSeen;
                    uint64_t cursor = bodyAddr;
                    bool validChain = true;
                    while (cursor && loop->blocks.count(cursor) &&
                           !chainSeen.count(cursor)) {
                        chainSeen.insert(cursor);
                        const CfgBlock* member = cfg.blockAt(cursor);
                        if (!member ||
                            (cfg.loopByHeader(cursor) &&
                             cursor != loop->header)) {
                            validChain = false;
                            break;
                        }
                        chain.push_back(cursor);
                        const PcodeInsn* memberTerm =
                            member->terminator();
                        if (memberTerm && memberTerm->kind == Insn::JMP &&
                            memberTerm->targetKnown &&
                            memberTerm->target == loop->header)
                            break; // chain end: the back edge
                        if (memberTerm && memberTerm->kind == Insn::JCC) {
                            validChain = false; // keep goto form
                            break;
                        }
                        if (member->succs.size() == 1 &&
                            loop->blocks.count(member->succs[0])) {
                            cursor = member->succs[0];
                        } else {
                            validChain = false;
                            break;
                        }
                    }
                    if (validChain && !chain.empty()) {
                        BlockEmitter header(*b);
                        header.indent = depth + 1;
                        header.nameOf = nameOf;
                    header.guardSlotOf = guardSlotOf;
                        header.signatureOf = signatureOf;
                        header.architecture = architecture;
                        header.useRecoveredRuntime = useRecoveredRuntime;
                        header.stackModel = stackModel;
                        header.globals = globals;
                        header.spBias = frameBias;
                        header.entryBlock = !useRecoveredRuntime && (a == start);
header.liveFlags = &liveFlags;
header.liveOut = livenessEnabled ? findLiveSet(liveOut, b->start) : nullptr;
header.liveOutCall = livenessEnabled ? findLiveSet(liveOutCall, b->start) : nullptr;
header.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
header.readPos = livenessEnabled ? findReadPos(blockReadPos, b->start) : nullptr;
header.memRead = read;


header.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
header.pushSlots = &pushSlots;
                        header.emit();
                        if (header.out.str().empty() && header.hasCond &&
                            !header.cond.empty()) {
                            const bool targetEnters =
                                headerTerm->target == bodyAddr;
                            const bool fallEnters =
                                b->succs[0] == bodyAddr;
                            if (targetEnters || fallEnters) {
                                const std::string condition =
                                    targetEnters
                                        ? header.cond
                                        : "!(" + header.cond + ")";
                                for (int i = 0; i <= depth; ++i)
                                    out << "    ";
                                out << "while (" << condition << ") {\n";
                                suppressBackedgeTo = loop->header;
                                for (uint64_t member : chain)
                                    emitBlock(member, depth + 1);
                                suppressBackedgeTo = std::nullopt;
                                for (uint64_t member : chain)
                                    emitted.insert(member);
                                for (int i = 0; i <= depth; ++i)
                                    out << "    ";
                                out << "}\n";
                                emitBlock(loop->exits.front().second,
                                          depth);
                                return;
                            }
                        }
                    }
                }
            }
        }

        BlockEmitter be(*b);
        be.indent = depth + 1;
        be.nameOf = nameOf;
                    be.guardSlotOf = guardSlotOf;
        be.signatureOf = signatureOf;
        be.architecture = architecture;
        be.useRecoveredRuntime = useRecoveredRuntime;
                    be.stackModel = stackModel;
    be.globals = globals;

        be.spBias = frameBias;

        be.entryBlock = !useRecoveredRuntime && (a == start);
be.liveFlags = &liveFlags;
be.liveOut = livenessEnabled ? findLiveSet(liveOut, b->start) : nullptr;
be.liveOutCall = livenessEnabled ? findLiveSet(liveOutCall, b->start) : nullptr;
be.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
be.readPos = livenessEnabled ? findReadPos(blockReadPos, b->start) : nullptr;
be.memRead = read;


be.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, b->start) : nullptr;
be.pushSlots = &pushSlots;
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
            const CfgBlock* fb = cfg.blockAt(fall);
            if (tb && fb && target != fall && !tb->isRet() && !fb->isRet() &&
                tb->succs.size() == 1 && fb->succs.size() == 1 &&
                tb->succs[0] == fb->succs[0] &&
                cfg.predecessors(target).size() == 1 &&
                cfg.predecessors(fall).size() == 1 &&
                !emitted.count(target) && !emitted.count(fall)) {
                BlockEmitter thenBody(*tb);
                thenBody.indent = depth + 2;
                thenBody.nameOf = nameOf;
                    thenBody.guardSlotOf = guardSlotOf;
                thenBody.signatureOf = signatureOf;
                thenBody.architecture = architecture;
                thenBody.useRecoveredRuntime = useRecoveredRuntime;
                    thenBody.stackModel = stackModel;
    thenBody.globals = globals;

                thenBody.spBias = frameBias;

                thenBody.entryBlock = !useRecoveredRuntime && (a == start);
thenBody.liveFlags = &liveFlags;
thenBody.liveOut = livenessEnabled ? findLiveSet(liveOut, tb->start) : nullptr;
thenBody.liveOutCall = livenessEnabled ? findLiveSet(liveOutCall, tb->start) : nullptr;
thenBody.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, tb->start) : nullptr;
thenBody.readPos = livenessEnabled ? findReadPos(blockReadPos, tb->start) : nullptr;
thenBody.memRead = read;


thenBody.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, tb->start) : nullptr;
thenBody.pushSlots = &pushSlots;
                thenBody.emit();
                BlockEmitter elseBody(*fb);
                elseBody.indent = depth + 2;
                elseBody.nameOf = nameOf;
                    elseBody.guardSlotOf = guardSlotOf;
                elseBody.signatureOf = signatureOf;
                elseBody.architecture = architecture;
                elseBody.useRecoveredRuntime = useRecoveredRuntime;
                    elseBody.stackModel = stackModel;
    elseBody.globals = globals;

                elseBody.spBias = frameBias;

                elseBody.entryBlock = !useRecoveredRuntime && (a == start);
elseBody.liveFlags = &liveFlags;
elseBody.liveOut = livenessEnabled ? findLiveSet(liveOut, fb->start) : nullptr;
elseBody.liveOutCall = livenessEnabled ? findLiveSet(liveOutCall, fb->start) : nullptr;
elseBody.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, fb->start) : nullptr;
elseBody.readPos = livenessEnabled ? findReadPos(blockReadPos, fb->start) : nullptr;
elseBody.memRead = read;


elseBody.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, fb->start) : nullptr;
elseBody.pushSlots = &pushSlots;
                elseBody.emit();
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "if (" << be.cond << ") {\n" << thenBody.out.str();
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "} else {\n" << elseBody.out.str();
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "}\n";
                emitted.insert(target);
                emitted.insert(fall);
                frameBias = std::min({frameBias, thenBody.spBias,
                                      elseBody.spBias});
                emitBlock(tb->succs[0], depth);
                return;
            }
            if (tb && tb->isRet() && cfg.predecessors(target).size() == 1) {
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "if (" << be.cond << ") {\n";
                BlockEmitter te(*tb);
                te.indent = depth + 2;
                te.nameOf = nameOf;
                    te.guardSlotOf = guardSlotOf;
                te.signatureOf = signatureOf;
                te.architecture = architecture;
                te.useRecoveredRuntime = useRecoveredRuntime;
                    te.stackModel = stackModel;
    te.globals = globals;

                te.spBias = frameBias;

                te.entryBlock = !useRecoveredRuntime && (a == start);
te.liveFlags = &liveFlags;
te.liveOut = livenessEnabled ? findLiveSet(liveOut, tb->start) : nullptr;
te.liveOutCall = livenessEnabled ? findLiveSet(liveOutCall, tb->start) : nullptr;
te.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, tb->start) : nullptr;
te.readPos = livenessEnabled ? findReadPos(blockReadPos, tb->start) : nullptr;
te.memRead = read;


te.callArgsLocal = livenessEnabled ? findLiveSet(callArgsLocal, tb->start) : nullptr;
te.pushSlots = &pushSlots;
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
            if (!cfg.blockAt(target) && danglingLabels.insert(target).second) {
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << labelName(target) << ":;\n";
            }
            for (int i = 0; i <= depth; ++i) out << "    ";
            out << "if (" << be.cond << ") goto " << labelName(target)
                << ";\n";
            emitBlock(fall, depth);
            return;
        }
        if (b->tailCallTarget) {
            std::string args;
            const auto targetSignature = signatureOf
                                             ? signatureOf(*b->tailCallTarget)
                                             : std::optional<FunctionSignature>{};
            const size_t argumentCount = targetSignature
                                             ? targetSignature->parameters.size() : 8;
            const std::vector<uint64_t> fallback =
                defaultArgumentRegisters(architecture);
            for (size_t i = 0; i < argumentCount; ++i) {
                const uint64_t offset = targetSignature
                                            ? targetSignature->parameters[i].registerOffset
                                            : fallback[std::min(i, fallback.size() - 1)];
                const bool stackArgument = targetSignature &&
                                           targetSignature->parameters[i].onStack;
                std::string argument;
                if (stackArgument) {
                    const std::string address =
                        registerName(architecture,
                                     stackPointerOffset(architecture)) +
                        " + " +
                        std::to_string(targetSignature->parameters[i].stackOffset);
                    argument = useRecoveredRuntime
                        ? "recovered_load<std::uint64_t>(" + address + ")"
                        : "*((uint64_t *)(uintptr_t)(" +
                              be.rebaseText(address) + "))";
                } else {
                    argument = registerName(architecture, offset);
                }
                args += (i ? ", " : "") + argument;
            }
            for (int i = 0; i <= depth; ++i) out << "    ";
            if (targetSignature &&
                targetSignature->returnType.kind == TypeKind::VOID_TYPE) {
                out << nameOf(*b->tailCallTarget) << "(" << args << ");\n";
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << "return "
                    << registerName(architecture,
                                    returnRegisterOffset(architecture))
                    << ";\n";
            } else {
                out << "return " << nameOf(*b->tailCallTarget) << "(" << args
                    << ");\n";
            }
            return;
        }
        if (term->kind == Insn::JMP && term->targetKnown) {
            if (suppressBackedgeTo && term->target == *suppressBackedgeTo) {
                // Structured loop backedge: the while/do-while condition
                // already covers it - emit nothing.
                return;
            }
            if (!cfg.blockAt(term->target) &&
                danglingLabels.insert(term->target).second) {
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << labelName(term->target) << ":;\n";
            }
            for (int i = 0; i <= depth; ++i) out << "    ";
            out << "goto " << labelName(term->target) << ";\n";
            return;
        }
        if (be.resolvedKnown && (term->kind == Insn::JMP ||
                                 term->kind == Insn::OTHER)) {
            if (!cfg.blockAt(be.resolvedTarget) &&
                danglingLabels.insert(be.resolvedTarget).second) {
                for (int i = 0; i <= depth; ++i) out << "    ";
                out << labelName(be.resolvedTarget) << ":;\n";
            }
            for (int i = 0; i <= depth; ++i) out << "    ";
            out << "goto " << labelName(be.resolvedTarget) << ";\n";
            return;
        }
        // Indirect-jump trampoline: `mov reg, [rip+slot]; jmp *reg` (a
        // data-slot jump board, common in recovered CRT/allocator thunks).
        // The target is a runtime memory load, so it cannot be resolved
        // statically - but the jump itself is a tail call.  Previously the
        // BRANCHIND op was silently skipped and the function decompiled to
        // a void body with a dead load, dropping the dispatch.  Emit a
        // dispatch through the register holding the loaded value and
        // forward the live ABI argument registers (native thunks forward
        // the caller's registers untouched).
        if ((term->kind == Insn::JMP || term->kind == Insn::OTHER) &&
            !term->targetKnown && !be.resolvedKnown) {
            std::string targetRegister;
            std::optional<std::string> memoryTarget;
            for (const auto& op : term->ops) {
                if (op.op != POp::BRANCHIND && op.op != POp::BRANCH)
                    continue;
                uint64_t storage = 0;
                bool storageValid = false;
                const Varnode* v = term->find(op.in0);
                if (!v) continue;
                if (v->kind == Varnode::REGISTER) {
                    storage = registerStorageOffset(architecture, v->offset,
                                                    v->size);
                    storageValid = true;
                } else if (v->kind == Varnode::UNIQUE) {
                    // Trace a temp back to its defining op: a COPY carries
                    // a register value (`mov reg,[slot]; jmp *reg`); an
                    // INT_ADD/INT_SUB of a register and a constant is a
                    // memory-indirect jump (`jmp qword ptr [reg+K]`, e.g.
                    // vtable tail calls) whose target is the loaded value.
                    for (const auto& defining : term->ops) {
                        if (defining.out != v->id) continue;
                        if (defining.op == POp::COPY) {
                            const Varnode* source =
                                term->find(defining.in0);
                            if (source &&
                                source->kind == Varnode::REGISTER) {
                                storage = registerStorageOffset(
                                    architecture, source->offset,
                                    source->size);
                                storageValid = true;
                            }
                        } else if (defining.op == POp::INT_ADD ||
                                   defining.op == POp::INT_SUB) {
                            const Varnode* a = term->find(defining.in0);
                            const Varnode* b = term->find(defining.in1);
                            uint64_t regStorage = 0;
                            int64_t k = 0;
                            bool haveReg = false, haveK = false;
                            for (const Varnode* candidate : {a, b}) {
                                if (!candidate) continue;
                                if (candidate->kind == Varnode::REGISTER) {
                                    regStorage = registerStorageOffset(
                                        architecture, candidate->offset,
                                        candidate->size);
                                    haveReg = true;
                                } else if (candidate->kind ==
                                           Varnode::CONST) {
                                    k = static_cast<int64_t>(
                                        candidate->offset);
                                    haveK = true;
                                }
                            }
                            if (haveReg) {
                                std::string address =
                                    registerName(architecture, regStorage, 8);
                                const auto definition =
                                    be.regExpr.find(regStorage);
                                if (definition != be.regExpr.end() &&
                                    inlineableExpression(
                                        definition->second))
                                    address = stripParens(
                                        definition->second.text);
                                if (haveK)
                                    address += (defining.op == POp::INT_ADD
                                                    ? " + "
                                                    : " - ") +
                                               std::to_string(k);
                                memoryTarget = address;
                            }
                        }
                        break;
                    }
                }
                // Only a jump whose target register was written in this
                // block is a recognizable trampoline; a jump on an unknown
                // incoming value (e.g. a switch dispatch) stays a plain
                // fallthrough/return.
                if (memoryTarget) break;
                if (!storageValid) continue;
                if (be.regExpr.find(storage) == be.regExpr.end()) continue;
                targetRegister = registerName(architecture, storage, 8);
                break;
            }
            if (!targetRegister.empty() || memoryTarget) {
                std::string args;
                const std::vector<uint64_t> abi =
                    defaultArgumentRegisters(architecture);
                const size_t argumentCount =
                    useRecoveredRuntime ? 8 : abi.size();
                for (size_t i = 0; i < argumentCount; ++i) {
                    std::string text = "0";
                    if (i < abi.size()) {
                        const uint64_t offset = abi[i];
                        const uint64_t argStorage = registerStorageOffset(
                            architecture, offset, 8);
                        text = registerName(architecture, offset);
                        const auto definition = be.regExpr.find(argStorage);
                        if (definition != be.regExpr.end() &&
                            inlineableExpression(definition->second))
                            text = stripParens(definition->second.text);
                    }
                    args += (i ? ", " : "") + text;
                }
                for (int i = 0; i <= depth; ++i) out << "    ";
                if (useRecoveredRuntime) {
                    if (memoryTarget)
                        out << "return recovered_dispatch(recovered_load<"
                               "std::uint64_t>(" << *memoryTarget << "), "
                            << args << ");\n";
                    else
                        out << "return recovered_dispatch(" << targetRegister
                            << ", " << args << ");\n";
                } else {
                    if (memoryTarget)
                        out << "return ((uint64_t (*)(...))(uintptr_t)(*"
                               "(uint64_t *)(uintptr_t)(" << *memoryTarget
                            << ")))(" << args << ");\n";
                    else
                        out << "return ((uint64_t (*)(...))(uintptr_t)"
                            << targetRegister << ")(" << args << ");\n";
                }
                return;
            }
        }
        if (!b->succs.empty()) emitBlock(b->succs[0], depth);
    };

    emitBlock(start, 0);
    // emit any blocks only reachable via branches (never on a fallthrough
    // path), so every label is defined
    for (const auto& b : cfg.blocks())
        if (!emitted.count(b.start)) emitBlock(b.start, 0);
    // Safety net: when function-boundary analysis merges blocks from an
    // adjacent function into this CFG, a branch can reference a label that
    // never got emitted (the block sits before `start` or was pruned).
    // Undefined labels break compilation, so append a dangling definition
    // for every referenced-but-missing label.
    {
        const std::string text = out.str();
        std::set<uint64_t> referenced, defined;
        const std::regex gotoPattern(
            R"(goto L(0x[0-9a-fA-F]+);)");
        const std::regex labelPattern(R"(L(0x[0-9a-fA-F]+):)");
        for (std::sregex_iterator it(text.begin(), text.end(), gotoPattern),
             end;
             it != end; ++it)
            referenced.insert(
                static_cast<uint64_t>(std::stoull((*it)[1].str(), nullptr, 16)));
        for (std::sregex_iterator it(text.begin(), text.end(), labelPattern),
             end;
             it != end; ++it)
            defined.insert(
                static_cast<uint64_t>(std::stoull((*it)[1].str(), nullptr, 16)));
        for (uint64_t missing : referenced) {
            if (defined.count(missing)) continue;
            out << labelName(missing) << ":;\n";
        }
    }
    return renameAbiRoles(out.str(), architecture);
}

std::string decompileTyped(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end, const std::string& architecture, const std::string& functionName,
    const FunctionSignature& signature,
    const std::function<std::string(uint64_t)>& nameOf,
    const std::function<std::optional<FunctionSignature>(uint64_t)>& signatureOf) {
    return decompileTyped(eng, read, start, end, architecture, functionName,
                          signature, nameOf, signatureOf, false, nullptr,
                          nullptr);
}

std::string decompileTyped(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end, const std::string& architecture, const std::string& functionName,
    const FunctionSignature& signature,
    const std::function<std::string(uint64_t)>& nameOf,
    const std::function<std::optional<FunctionSignature>(uint64_t)>& signatureOf,
    bool useRecoveredRuntime, const StackFrameModel* stackModel,
    const GlobalObjectRecovery* globals,
    const std::function<bool(uint64_t)>& guardSlotOf) {
    std::string body = decompile(eng, read, start, end, nameOf, signatureOf,
                                 architecture, useRecoveredRuntime,
                                 stackModel, globals, guardSlotOf);
    // A data-slot trampoline (indirect tail call) forwards the callee's
    // return value through rax, so it must never decompile to void: the
    // typed wrapper's void-return rewrite would turn the dispatch into a
    // bare statement and the recovered dispatch case would return 0,
    // breaking allocator jump boards (callers observe NULL and memset(0)
    // crashes downstream).  Promote the signature to a 64-bit value return
    // when the body carries a tail-call dispatch.
    FunctionSignature effectiveSignature = signature;
    // ABI-role register names (arg0, ret_val, ...) can collide with
    // signature parameter names - inferSignature names parameters arg0..,
    // which is exactly the riscv/win64 argument naming.  For any role
    // that collides, revert the register to its architectural name in the
    // body so the wrapper stays compilable (parameter arg0 + register a0).
    {
        std::set<std::string> parameterNames;
        for (const FunctionParameter& parameter : effectiveSignature.parameters)
            parameterNames.insert(parameter.name);
        const int registerCount =
            architecture.rfind("x86", 0) == 0 ? 16 : 32;
        for (int index = 0; index < registerCount; ++index) {
            const uint64_t offset = static_cast<uint64_t>(index) * 8;
            const std::string role = abiRoleName(architecture, offset);
            if (role != registerName(architecture, offset, 8) &&
                parameterNames.count(role))
                body = replaceIdentifier(body, role,
                                         registerName(architecture, offset, 8));
        }
    }
    // The register name to declare/bind for an offset: the ABI role, or the
    // architectural name when the role collides with a parameter name.
    auto registerDeclName = [&](uint64_t offset) {
        const std::string role = abiRoleName(architecture, offset);
        for (const FunctionParameter& parameter : effectiveSignature.parameters)
            if (parameter.name == role)
                return registerName(architecture, offset, 8);
        return role;
    };
    if (effectiveSignature.returnType.kind == TypeKind::VOID_TYPE &&
        (body.find("return recovered_dispatch(") != std::string::npos ||
         body.find("return ((uint64_t (*)(...))(uintptr_t)") !=
             std::string::npos))
        effectiveSignature.returnType =
            DataType{TypeKind::UNSIGNED_INT, 64, 1};
    std::set<std::string> locals;
    std::map<std::string, std::vector<std::string>> typedLocals;
    if (stackModel) {
        // Native Source Backend: promoted slots declare their recovered
        // width; the text scan below still picks up un-promoted fallbacks.
        for (const StackSlot& ss : stackModel->slots) {
            if (ss.promoted && !ss.typeName.empty() &&
                !ss.variableName.empty())
                typedLocals[ss.typeName].push_back(ss.variableName);
        }
    }
    for (size_t at = 0; (at = body.find("saved_", at)) != std::string::npos;) {
        size_t finish = at + 6;
        while (finish < body.size() &&
               (std::isalnum(static_cast<unsigned char>(body[finish])) ||
                body[finish] == '_'))
            ++finish;
        locals.insert(body.substr(at, finish - at));
        at = finish;
    }
    for (size_t at = 0; (at = body.find("local_", at)) != std::string::npos;) {
        size_t finish = at + 6;
        while (finish < body.size() &&
               (std::isalnum(static_cast<unsigned char>(body[finish])) ||
                body[finish] == '_'))
            ++finish;
        const std::string name = body.substr(at, finish - at);
        bool promoted = false;
        for (const auto& kv : typedLocals)
            if (std::find(kv.second.begin(), kv.second.end(), name) !=
                kv.second.end())
                promoted = true;
        if (!promoted) locals.insert(name);
        at = finish;
    }
    for (const FunctionParameter& parameter : effectiveSignature.parameters)
        if (parameter.onStack && !useRecoveredRuntime)
            locals.insert(localName(parameter.stackOffset));
    auto identifierUsed = [&](const std::string& identifier) {
        for (size_t at = 0; (at = body.find(identifier, at)) != std::string::npos;
             at += identifier.size()) {
            const bool left = at == 0 ||
                !(std::isalnum(static_cast<unsigned char>(body[at - 1])) ||
                  body[at - 1] == '_');
            const size_t after = at + identifier.size();
            const bool right = after == body.size() ||
                !(std::isalnum(static_cast<unsigned char>(body[after])) ||
                  body[after] == '_');
            if (left && right) return true;
        }
        return false;
    };
    std::ostringstream out;
    out << effectiveSignature.declaration(functionName) << " {\n";
    {
        const int registerCount = architecture.rfind("x86", 0) == 0 ? 16 : 32;
        std::vector<std::string> usedRegisters;
        for (int index = 0; index < registerCount; ++index) {
            const std::string name = registerDeclName(
                static_cast<uint64_t>(index) * 8);
            bool parameterRegister = false;
            for (const FunctionParameter& parameter : effectiveSignature.parameters)
                parameterRegister |= parameter.registerOffset ==
                                     static_cast<uint64_t>(index * 8);
            if (effectiveSignature.returnComponents.size() > 1)
                parameterRegister |= secondaryReturnRegisterOffset(architecture) ==
                                     static_cast<uint64_t>(index * 8);
            if (name != "zero" && (identifierUsed(name) || parameterRegister))
                usedRegisters.push_back(name);
        }
        // Architecture specifications may expose status, mask, or virtual
        // registers outside the conventional integer-register bank.  Their
        // fallback names are r<offset>; discover every such identifier used
        // by the emitted body so generated C/C++ never references an
        // undeclared architectural register (for example x86 flag r512).
        for (size_t at = 0; at < body.size();) {
            if (body[at] != 'r' || at + 1 >= body.size() ||
                !std::isdigit(static_cast<unsigned char>(body[at + 1]))) {
                ++at;
                continue;
            }
            const bool leftBoundary = at == 0 ||
                !(std::isalnum(static_cast<unsigned char>(body[at - 1])) ||
                  body[at - 1] == '_');
            size_t finish = at + 1;
            while (finish < body.size() &&
                   std::isdigit(static_cast<unsigned char>(body[finish])))
                ++finish;
            const bool rightBoundary = finish == body.size() ||
                !(std::isalnum(static_cast<unsigned char>(body[finish])) ||
                  body[finish] == '_');
            if (leftBoundary && rightBoundary) {
                const std::string name = body.substr(at, finish - at);
                if (std::find(usedRegisters.begin(), usedRegisters.end(), name) ==
                    usedRegisters.end())
                    usedRegisters.push_back(name);
            }
            at = finish;
        }
        if (architecture.rfind("x86", 0) == 0) {
            for (const char* segmentBase : {"fsbase", "gsbase"})
                if (identifierUsed(segmentBase) &&
                    std::find(usedRegisters.begin(), usedRegisters.end(),
                              segmentBase) == usedRegisters.end())
                    usedRegisters.push_back(segmentBase);
        }
        if (!usedRegisters.empty()) {
            out << "    uint64_t ";
            for (size_t index = 0; index < usedRegisters.size(); ++index)
                out << (index ? ", " : "") << usedRegisters[index] << " = 0";
            out << ";\n";
        }
        const struct {
            const char* prefix;
            const char* type;
            int count;
        } vectorBanks[] = {
            {"xmm", "RecoveredVector128", 32},
            {"ymm", "RecoveredVector256", 32},
            {"zmm", "RecoveredVector512", 32},
        };
        for (const auto& bank : vectorBanks) {
            std::vector<std::string> used;
            for (int index = 0; index < bank.count; ++index) {
                const std::string name = std::string(bank.prefix) +
                                         std::to_string(index);
                if (identifierUsed(name)) used.push_back(name);
            }
            if (used.empty()) continue;
            out << "    " << bank.type << " ";
            for (size_t index = 0; index < used.size(); ++index)
                out << (index ? ", " : "") << used[index] << "{}";
            out << ";\n";
        }
        if (architecture.rfind("x86", 0) == 0) {
            std::vector<std::string> usedSt;
            for (int index = 0; index < 8; ++index) {
                const std::string name = "st" + std::to_string(index);
                if (identifierUsed(name))
                    usedSt.push_back(name);
            }
            if (!usedSt.empty()) {
                out << "    uint64_t ";
                for (size_t index = 0; index < usedSt.size(); ++index)
                    out << (index ? ", " : "") << usedSt[index] << " = 0";
                out << ";\n";
            }
        }
        if (useRecoveredRuntime && architecture.rfind("x86", 0) == 0 &&
            identifierUsed("rsp")) {
            out << "    RecoveredStackFrame recovered_stack_frame;\n"
                << "    rsp = recovered_stack_frame.pointer();\n";
        }
        if (useRecoveredRuntime && architecture.rfind("x86", 0) == 0) {
            if (identifierUsed("fsbase"))
                out << "    fsbase = recovered_fs_base();\n";
            if (identifierUsed("gsbase"))
                out << "    gsbase = recovered_gs_base();\n";
        }
        for (const FunctionParameter& parameter : effectiveSignature.parameters) {
            if (parameter.onStack) continue;
            const std::string name = registerDeclName(parameter.registerOffset);
            out << "    " << name << " = (uint64_t)(uintptr_t)"
                << parameter.name << ";\n";
        }
    }
    if (!locals.empty()) {
        out << "    uint64_t ";
        size_t index = 0;
        for (const std::string& local : locals)
            out << (index++ ? ", " : "") << local << " = 0";
        out << ";\n";
    }
    if (!typedLocals.empty()) {
        for (const auto& kv : typedLocals)
            for (const std::string& name : kv.second)
                out << "    " << kv.first << " " << name << " = 0;\n";
    }
    for (const FunctionParameter& parameter : effectiveSignature.parameters)
        if (parameter.onStack) {
            if (useRecoveredRuntime)
                out << "    recovered_store<std::uint64_t>(" +
                           registerDeclName(stackPointerOffset(architecture)) +
                           " + " + std::to_string(parameter.stackOffset) +
                           ", " + parameter.name + ");\n";
            else
                out << "    " << localName(parameter.stackOffset)
                    << " = (uint64_t)(uintptr_t)" << parameter.name << ";\n";
        }
    std::istringstream lines(body);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind("// decompiled", 0) == 0) continue;
        const size_t first = line.find_first_not_of(' ');
        const std::string machineReturn = "return " +
            registerDeclName(returnRegisterOffset(architecture)) + ";";
        if (effectiveSignature.returnType.kind == TypeKind::VOID_TYPE &&
            first != std::string::npos && line.substr(first) == machineReturn)
            line = line.substr(0, first) + "return;";
        else if (effectiveSignature.returnType.kind == TypeKind::VOID_TYPE &&
                 first != std::string::npos &&
                 line.compare(first, 7, "return ") == 0) {
            const std::string indentation = line.substr(0, first);
            line = indentation + line.substr(first + 7) + "\n" +
                   indentation + "return;";
        }
        else if (effectiveSignature.returnType.kind == TypeKind::POINTER &&
                 first != std::string::npos && line.substr(first) == machineReturn)
            line = line.substr(0, first) + "return (void *)(uintptr_t)" +
                   registerDeclName(returnRegisterOffset(architecture)) + ";";
        else if (effectiveSignature.returnComponents.size() > 1 &&
                 effectiveSignature.returnType.kind == TypeKind::STRUCT &&
                 effectiveSignature.returnType.detail &&
                 first != std::string::npos && line.substr(first) == machineReturn)
            line = line.substr(0, first) + "return (struct " +
                   effectiveSignature.returnType.detail->name + "){ " +
                   registerDeclName(returnRegisterOffset(architecture)) +
                   ", " + registerDeclName(
                       secondaryReturnRegisterOffset(architecture)) +
                   " };";
        out << line << "\n";
    }
    if (effectiveSignature.returnType.kind == TypeKind::VOID_TYPE)
        out << "    return;\n";
    else if (effectiveSignature.returnType.kind == TypeKind::FLOAT)
        out << "    return 0.0;\n";
    else if ((effectiveSignature.returnType.kind == TypeKind::STRUCT ||
              effectiveSignature.returnType.kind == TypeKind::UNION) &&
             effectiveSignature.returnType.detail)
        out << "    return (" << effectiveSignature.returnType.name() << "){0};\n";
    else
        out << "    return 0;\n";
    out << "}\n";
    return out.str();
}

} // namespace centrifuge
