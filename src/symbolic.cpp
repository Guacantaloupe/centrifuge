// centrifuge - a Ghidra reimplementation in C++17
// symbolic.cpp - a small angr-style symbolic execution engine
//
// The engine lifts machine code through the existing Sleigh engine and
// executes p-code over symbolic bit-vectors.  Input bytes (stdin reads or
// seeded memory ranges) are the only symbolic leaves; everything else
// concretizes or prunes.  Exploration is BFS with per-state step limits and
// per-address revisit (loop) bounds.  Path constraints are solved by
// interval narrowing over the input-byte domains, verified by concrete
// evaluation before a solution is reported.
#include "centrifuge/symbolic.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <sstream>

#include "centrifuge/pcode.hpp"

namespace centrifuge {
namespace {

// ---------------------------------------------------------------------------
// Symbolic bit-vector expressions
// ---------------------------------------------------------------------------

enum class NK {
    Const, Input,
    Add, Sub, Mul, Div, Rem,
    And, Or, Xor, Shl, Shr, Sar,
    Not, Neg, Carry, Borrow,
    Zext, Sext, Piece, Extract, ITE,
    Cmp,  // comparison result: pred in aux, children a, b (same width)
    Unknown,  // unmodelled op result: full-range, concretizes to 0
};

enum class Pred : uint8_t {
    Eq, Ne, Ult, Ule, Ugt, Uge, Slt, Sle, Sgt, Sge,
};

Pred complement(Pred p) {
    switch (p) {
    case Pred::Eq: return Pred::Ne;
    case Pred::Ne: return Pred::Eq;
    case Pred::Ult: return Pred::Uge;
    case Pred::Ule: return Pred::Ugt;
    case Pred::Ugt: return Pred::Ule;
    case Pred::Uge: return Pred::Ult;
    case Pred::Slt: return Pred::Sge;
    case Pred::Sle: return Pred::Sgt;
    case Pred::Sgt: return Pred::Sle;
    case Pred::Sge: return Pred::Slt;
    }
    return Pred::Eq;
}

struct Node;
using Sym = std::shared_ptr<const Node>;

struct Node {
    NK kind = NK::Const;
    int size = 8;            // bytes
    uint64_t value = 0;      // Const
    uint32_t index = 0;      // Input: byte index
    int aux = 0;             // Extract: byte shift; Cmp: pred; ITE/Mul/etc
    Pred pred = Pred::Eq;    // Cmp
    Sym a, b, c;
};

uint64_t maskOf(int bytes) {
    if (bytes >= 8) return ~0ULL;
    return (1ULL << (bytes * 8)) - 1;
}

uint64_t truncOf(uint64_t v, int bytes) {
    return v & maskOf(bytes);
}

Sym node(NK k, int size, Sym a = nullptr, Sym b = nullptr, Sym c = nullptr) {
    auto n = std::make_shared<Node>();
    n->kind = k;
    n->size = size;
    n->a = std::move(a);
    n->b = std::move(b);
    n->c = std::move(c);
    return n;
}

Sym con(uint64_t v, int size) {
    auto n = std::make_shared<Node>();
    n->kind = NK::Const;
    n->size = size;
    n->value = truncOf(v, size);
    return n;
}

Sym input(uint32_t index) {
    auto n = std::make_shared<Node>();
    n->kind = NK::Input;
    n->size = 1;
    n->index = index;
    return n;
}

// Fresh unconstrained value for unmodelled ops (e.g. parity flag).  Full
// range during exploration; pinned to 0 for concrete model verification, so
// results are never false positives (at worst a missed path).
Sym unknownSym(int size) {
    static uint32_t counter = 0;
    auto n = std::make_shared<Node>();
    n->kind = NK::Unknown;
    n->size = size;
    n->index = ++counter;
    return n;
}

// Input byte leaf honoring a concrete replay model when configured.
struct InputFactory {
    const std::vector<uint8_t>* concrete = nullptr;
    Sym make(uint32_t index) const {
        if (concrete && index < concrete->size())
            return con((*concrete)[index], 1);
        return input(index);
    }
};

std::optional<uint64_t> asConst(const Sym& s) {
    if (s && s->kind == NK::Const) return s->value;
    return std::nullopt;
}

uint64_t evalCmp(Pred p, uint64_t a, uint64_t b, int size);

Sym cmpNode(Pred p, Sym a, Sym b) {
    if (auto v = asConst(a))
        if (auto w = asConst(b))
            return con(evalCmp(p, *v, *w, a->size), 1);
    const int size = std::max(a->size, b->size);
    auto n = std::make_shared<Node>();
    n->kind = NK::Cmp;
    n->size = 1;
    n->pred = p;
    n->a = std::move(a);
    n->b = std::move(b);
    (void)size;
    return n;
}

// Constant folding constructors.
Sym mkAdd(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v + *w, a->size);
    if (asConst(a) && *asConst(a) == 0) return b;
    if (asConst(b) && *asConst(b) == 0) return a;
    return node(NK::Add, a->size, a, b);
}
Sym mkSub(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v - *w, a->size);
    if (asConst(b) && *asConst(b) == 0) return a;
    return node(NK::Sub, a->size, a, b);
}
Sym mkMul(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v * *w, a->size);
    if ((asConst(a) && *asConst(a) == 0) || (asConst(b) && *asConst(b) == 0))
        return con(0, a->size);
    if (asConst(a) && *asConst(a) == 1) return b;
    if (asConst(b) && *asConst(b) == 1) return a;
    return node(NK::Mul, a->size, a, b);
}
Sym mkAnd(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v & *w, a->size);
    if ((asConst(a) && *asConst(a) == 0) || (asConst(b) && *asConst(b) == 0))
        return con(0, a->size);
    if (asConst(a) && *asConst(a) == maskOf(a->size)) return b;
    if (asConst(b) && *asConst(b) == maskOf(a->size)) return a;
    return node(NK::And, a->size, a, b);
}
Sym mkOr(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v | *w, a->size);
    if (asConst(a) && *asConst(a) == 0) return b;
    if (asConst(b) && *asConst(b) == 0) return a;
    return node(NK::Or, a->size, a, b);
}
Sym mkNot(Sym a);
Sym mkNeg(Sym a);
Sym mkXor(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v ^ *w, a->size);
    if (asConst(a) && *asConst(a) == 0) return b;
    if (asConst(b) && *asConst(b) == 0) return a;
    if (asConst(a) && *asConst(a) == maskOf(a->size)) return mkNot(b);
    if (asConst(b) && *asConst(b) == maskOf(a->size)) return mkNot(a);
    return node(NK::Xor, a->size, a, b);
}
Sym mkNot(Sym a) {
    if (auto v = asConst(a)) return con(~*v, a->size);
    return node(NK::Not, a->size, a);
}
Sym mkNeg(Sym a) {
    if (auto v = asConst(a)) return con(0 - *v, a->size);
    return node(NK::Neg, a->size, a);
}
Sym mkShl(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v << (*w & 63), a->size);
    if (asConst(b) && *asConst(b) == 0) return a;
    return node(NK::Shl, a->size, a, b);
}
Sym mkShr(Sym a, Sym b) {
    if (auto v = asConst(a)) if (auto w = asConst(b)) return con(*v >> (*w & 63), a->size);
    if (asConst(b) && *asConst(b) == 0) return a;
    return node(NK::Shr, a->size, a, b);
}
Sym mkSar(Sym a, Sym b) {
    if (auto v = asConst(a)) {
        if (auto w = asConst(b)) {
            const int bits = a->size * 8;
            const uint64_t m = maskOf(a->size);
            uint64_t s = *v & m;
            const uint64_t sign = bits >= 64 ? (s >> 63) : (s >> (bits - 1)) & 1;
            if (sign) s |= ~m;
            return con((static_cast<int64_t>(s) >> (*w & 63)) & m, a->size);
        }
    }
    return node(NK::Sar, a->size, a, b);
}
Sym mkZext(Sym a, int toSize) {
    if (auto v = asConst(a)) return con(*v, toSize);
    if (a->size == toSize) return a;
    return node(NK::Zext, toSize, a);
}
Sym mkSext(Sym a, int toSize) {
    if (auto v = asConst(a)) {
        const int bits = a->size * 8;
        uint64_t s = *v;
        if (bits < 64 && (s >> (bits - 1)) & 1) s |= ~maskOf(a->size);
        return con(s, toSize);
    }
    if (a->size == toSize) return a;
    return node(NK::Sext, toSize, a);
}
Sym mkPiece(Sym hi, Sym lo) {
    if (auto v = asConst(hi)) if (auto w = asConst(lo))
        return con((*v << (lo->size * 8)) | *w, hi->size + lo->size);
    auto n = node(NK::Piece, hi->size + lo->size, hi, lo);
    return n;
}
Sym mkExtract(Sym a, int byteShift) {
    if (byteShift == 0 && a->size > 0) {
        // narrowing handled by caller via size
    }
    if (auto v = asConst(a)) return con(*v >> (byteShift * 8), a->size - byteShift);
    auto n = std::make_shared<Node>();
    n->kind = NK::Extract;
    n->size = a->size - byteShift;
    n->aux = byteShift;
    n->a = a;
    return n;
}

uint64_t evalCmp(Pred p, uint64_t a, uint64_t b, int size) {
    const uint64_t m = maskOf(size);
    a &= m; b &= m;
    const bool signBit = size < 8 && ((m >> 1) + 1) != 0;
    (void)signBit;
    const int64_t sa = size == 8 ? static_cast<int64_t>(a)
        : static_cast<int64_t>((a ^ ((m >> 1) + 1)) - ((m >> 1) + 1));
    const int64_t sb = size == 8 ? static_cast<int64_t>(b)
        : static_cast<int64_t>((b ^ ((m >> 1) + 1)) - ((m >> 1) + 1));
    switch (p) {
    case Pred::Eq: return a == b;
    case Pred::Ne: return a != b;
    case Pred::Ult: return a < b;
    case Pred::Ule: return a <= b;
    case Pred::Ugt: return a > b;
    case Pred::Uge: return a >= b;
    case Pred::Slt: return sa < sb;
    case Pred::Sle: return sa <= sb;
    case Pred::Sgt: return sa > sb;
    case Pred::Sge: return sa >= sb;
    }
    return 0;
}

Sym mkDiv(Sym a, Sym b, bool signedDiv, bool remainder) {
    if (auto w = asConst(b)) {
        if (*w == 0) return nullptr;  // caller prunes
        if (auto v = asConst(a)) {
            const uint64_t m = maskOf(a->size);
            uint64_t q = 0;
            if (signedDiv) {
                const int bits = a->size * 8;
                auto sx = [&](uint64_t x) {
                    if (bits < 64 && (x >> (bits - 1)) & 1) x |= ~m;
                    return static_cast<int64_t>(x);
                };
                const int64_t si = sx(*v), sj = sx(*w);
                if (sj == 0) return nullptr;
                if (remainder) q = static_cast<uint64_t>(si % sj);
                else q = static_cast<uint64_t>(si / sj);
            } else {
                if (remainder) q = *v % *w;
                else q = *v / *w;
            }
            return con(q, a->size);
        }
    }
    if (asConst(b) && !signedDiv && !remainder)
        return node(NK::Div, a->size, a, b);
    // symbolic divisor or signed/remainder forms: unsupported
    return nullptr;
}

// ---------------------------------------------------------------------------
// Interval evaluation over input-byte domains
// ---------------------------------------------------------------------------

struct Interval {
    uint64_t lo = 0, hi = 0;  // inclusive, within width mask
    bool empty = false;
};

struct Domains {
    std::vector<std::pair<uint64_t, uint64_t>> byte;  // [lo, hi] per input byte
};

Interval ivConst(uint64_t v, int size) {
    return {truncOf(v, size), truncOf(v, size), false};
}

// Unsigned interval of an expression; wraps clamp to full range (sound).
// Portable 65-bit arithmetic helpers (MSVC has no __uint128_t).
// addWide returns the carry out; a+b may need 65 bits.
inline uint64_t addWide(uint64_t a, uint64_t b, uint64_t& out) {
    out = a + b;
    return out < a ? 1 : 0;
}
// mulFits: true when a*b fits in 64 bits.
bool mulFits(uint64_t a, uint64_t b, uint64_t& out) {
    if (a != 0 && b > ~0ULL / a) return false;
    out = a * b;
    return true;
}

Interval ivEval(const Sym& e, const Domains& dom) {
    const uint64_t m = maskOf(e->size);
    switch (e->kind) {
    case NK::Const: return {e->value, e->value, false};
    case NK::Unknown: return {0, m, false};
    case NK::Input: {
        if (e->index >= dom.byte.size()) return {0, m, false};
        const auto& d = dom.byte[e->index];
        if (d.first > d.second) return {0, 0, true};
        return {truncOf(d.first, 1), truncOf(d.second, 1), false};
    }
    case NK::Zext: {
        Interval a = ivEval(e->a, dom);
        if (a.empty) return a;
        return {truncOf(a.lo, e->size), truncOf(a.hi, e->size), false};
    }
    case NK::Sext: {
        Interval a = ivEval(e->a, dom);
        if (a.empty) return a;
        const int bits = e->a->size * 8;
        if (bits >= 64) return {a.lo, a.hi, false};
        const uint64_t signBit = 1ULL << (bits - 1);
        if (a.hi & signBit) {
            // negative somewhere: high end extends to all-ones
            uint64_t lo = a.lo, hi = a.hi;
            if (a.lo & signBit) {
                lo |= ~maskOf(e->a->size);
                hi = m;
            } else {
                return {0, m, false};  // mixed sign: full range
            }
            return {truncOf(lo, e->size), truncOf(hi, e->size), false};
        }
        return {a.lo, a.hi, false};
    }
    case NK::Add: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        uint64_t lo = 0, hi = 0;
        const uint64_t clo = addWide(a.lo, b.lo, lo);
        const uint64_t chi = addWide(a.hi, b.hi, hi);
        // Wrap count of each end: how many times the sum exceeds the modulus.
        const int bits = e->size * 8;
        uint64_t cntLo = clo, cntHi = chi;
        if (bits < 64) {
            cntLo = (clo << (64 - bits)) | (lo >> bits);
            cntHi = (chi << (64 - bits)) | (hi >> bits);
        }
        if (cntLo != cntHi)
            return {0, m, false};  // wraps differently at the ends
        return {truncOf(lo, e->size), truncOf(hi, e->size), false};
    }
    case NK::Sub: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        if (a.lo >= b.hi && a.hi >= b.lo) {
            const uint64_t lo = a.lo - b.hi;
            const uint64_t hi = a.hi - b.lo;
            if (lo <= hi) return {lo, hi, false};
        }
        return {0, m, false};
    }
    case NK::Mul: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        uint64_t lo = 0, hi = 0;
        if (!mulFits(a.lo, b.lo, lo) || !mulFits(a.hi, b.hi, hi) ||
            lo > hi || lo > m || hi > m)
            return {0, m, false};
        return {lo, hi, false};
    }
    case NK::Div: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        if (b.lo == 0 || b.lo > b.hi) return {0, m, false};
        uint64_t hi = a.hi / b.lo;
        uint64_t lo = (a.lo == 0) ? 0 : a.lo / b.hi;
        if (lo > hi) std::swap(lo, hi);
        return {std::min(lo, m), std::min(hi, m), false};
    }
    case NK::And: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        if (a.lo == 0 && a.hi == m) return {0, b.hi, false};
        if (b.lo == 0 && b.hi == m) return {0, a.hi, false};
        return {0, std::min(a.hi, b.hi), false};
    }
    case NK::Or: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        if (a.lo == 0 && a.hi == m) return {b.lo, m, false};
        if (b.lo == 0 && b.hi == m) return {a.lo, m, false};
        return {std::max(a.lo, b.lo), m, false};
    }
    case NK::Xor: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        if ((a.lo == 0 && a.hi == m) || (b.lo == 0 && b.hi == m))
            return {0, m, false};
        return {0, m, false};  // xor is not interval-friendly
    }
    case NK::Not: {
        Interval a = ivEval(e->a, dom);
        if (a.empty) return a;
        return {truncOf(~a.hi, e->size), truncOf(~a.lo, e->size), false};
    }
    case NK::Neg: {
        Interval a = ivEval(e->a, dom);
        if (a.empty) return a;
        if (a.lo == 0 && a.hi == m) return {0, m, false};
        return {truncOf(0 - a.hi, e->size), truncOf(0 - a.lo, e->size), false};
    }
    case NK::Shl: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        if (b.lo == b.hi) {
            const unsigned s = static_cast<unsigned>(b.lo) & 63;
            if (s == 0) return a;
            if (a.lo > (m >> s) || a.hi > (m >> s)) return {0, m, false};
            return {a.lo << s, a.hi << s, false};
        }
        return {0, m, false};
    }
    case NK::Shr: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        return {a.lo >> (b.hi & 63), a.hi >> (b.lo & 63), false};
    }
    case NK::Sar: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        const int bits = e->size * 8;
        const uint64_t sign = bits >= 64 ? (1ULL << 63) : (1ULL << (bits - 1));
        if (a.hi & sign) return {0, a.hi >> (b.lo & 63), false};
        return {0, a.hi >> (b.lo & 63), false};
    }
    case NK::Piece: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        const int shift = e->b->size * 8;
        if (shift >= 64) return {0, m, false};
        if (a.lo > (m >> shift) || a.hi > (m >> shift)) return {0, m, false};
        const uint64_t lo = (a.lo << shift) | b.lo;
        const uint64_t hi = (a.hi << shift) | b.hi;
        if (lo > hi) return {0, m, false};
        return {lo, hi, false};
    }
    case NK::Extract: {
        Interval a = ivEval(e->a, dom);
        if (a.empty) return a;
        const int s = e->aux * 8;
        if (s >= 64) return {0, 0, false};
        return {truncOf(a.lo >> s, e->size), truncOf(a.hi >> s, e->size),
                false};
    }
    case NK::Cmp: {
        Interval a = ivEval(e->a, dom), b = ivEval(e->b, dom);
        if (a.empty || b.empty) return {0, 0, true};
        // definite answer only when intervals force it
        const bool definite = evalCmp(e->pred, a.lo, b.hi, e->a->size) ==
                              evalCmp(e->pred, a.hi, b.lo, e->a->size);
        if (definite)
            return {evalCmp(e->pred, a.lo, b.hi, e->a->size),
                    evalCmp(e->pred, a.lo, b.hi, e->a->size), false};
        return {0, 1, false};
    }
    case NK::ITE: {
        Interval t = ivEval(e->b, dom), f = ivEval(e->c, dom);
        if (t.empty || f.empty) return {0, 0, true};
        return {std::min(t.lo, f.lo), std::max(t.hi, f.hi), false};
    }
    case NK::Carry:
    case NK::Borrow:
        return {0, 1, false};
    case NK::Rem: {
        Interval b = ivEval(e->b, dom);
        if (b.empty) return b;
        if (b.hi == 0) return {0, 0, true};
        return {0, std::min(m, b.hi - 1), false};
    }
    }
    return {0, m, false};
}

// ---------------------------------------------------------------------------
// Interval narrowing: push a required range back through the expression and
// shrink input-byte domains.  Returns false when infeasible.
// ---------------------------------------------------------------------------

bool narrow(const Sym& e, uint64_t lo, uint64_t hi, Domains& dom) {
    const uint64_t m = maskOf(e->size);
    lo = truncOf(lo, e->size);
    hi = truncOf(hi, e->size);
    switch (e->kind) {
    case NK::Const:
        return !(e->value < lo || e->value > hi);
    case NK::Unknown:
        return true;  // no information about unmodelled values
    case NK::Input: {
        if (e->index >= dom.byte.size()) return true;  // unmodelled: no info
        auto& d = dom.byte[e->index];
        d.first = std::max(d.first, lo);
        d.second = std::min(d.second, hi);
        return d.first <= d.second;
    }
    case NK::Zext:
        return narrow(e->a, lo, hi, dom);
    case NK::Sext: {
        const int bits = e->a->size * 8;
        if (bits >= 64) return narrow(e->a, lo, hi, dom);
        const uint64_t signBit = 1ULL << (bits - 1);
        if (hi & signBit) {
            if (!(lo & signBit)) {
                // crosses sign boundary in extended space: split not worth it
                return true;
            }
            return narrow(e->a, truncOf(lo, e->a->size),
                          truncOf(hi, e->a->size), dom);
        }
        return narrow(e->a, lo, std::min(hi, maskOf(e->a->size)), dom);
    }
    case NK::Add: {
        Interval b = ivEval(e->b, dom);
        if (b.empty) return false;
        // a ⊆ [lo,hi] - b = [lo - b.hi, hi - b.lo]  (guarded on wrap)
        if (lo < b.hi || hi < b.lo) return true;  // negative end
        const uint64_t alo = lo - b.hi;
        const uint64_t ahi = hi - b.lo;
        if (alo > ahi) return true;  // cannot soundly narrow through wrap
        return narrow(e->a, alo, ahi, dom) && narrow(e->b, 0, m, dom);
    }
    case NK::Sub: {
        Interval b = ivEval(e->b, dom);
        if (b.empty) return false;
        uint64_t alo = 0, ahi = 0;
        if (addWide(lo, b.lo, alo) || addWide(hi, b.hi, ahi))
            return true;  // exceeds 64 bits, cannot represent
        if (ahi > m || alo > ahi) return true;
        return narrow(e->a, alo, ahi, dom);
    }
    case NK::Mul: {
        // only narrow constant multiples
        uint64_t k = 0;
        Sym var;
        if (auto c = asConst(e->a)) { k = *c; var = e->b; }
        else if (auto c = asConst(e->b)) { k = *c; var = e->a; }
        else return true;
        if (k == 0) return lo <= 0 && 0 <= hi;
        const uint64_t qlo = lo / k;
        const uint64_t qhi = hi / k + (hi % k ? 1 : 0);
        if (qhi > m) return true;
        return narrow(var, qlo, qhi, dom);
    }
    case NK::And: {
        uint64_t k = 0;
        Sym var;
        if (auto c = asConst(e->a)) { k = *c; var = e->b; }
        else if (auto c = asConst(e->b)) { k = *c; var = e->a; }
        else return true;
        // x & k ⊆ [lo,hi]  =>  lo & k <= x & k;  x ⊆ [lo, hi | ~k] is sound
        return narrow(var, lo, hi | ~k, dom);
    }
    case NK::Or: {
        uint64_t k = 0;
        Sym var;
        if (auto c = asConst(e->a)) { k = *c; var = e->b; }
        else if (auto c = asConst(e->b)) { k = *c; var = e->a; }
        else return true;
        return narrow(var, lo & ~k, hi, dom);
    }
    case NK::Not:
        return narrow(e->a, truncOf(~hi, e->size), truncOf(~lo, e->size),
                      dom);
    case NK::Neg: {
        if (lo == 0 && hi == m) return true;
        // -x ⊆ [lo,hi] with x in [0,m]: only x=0 survives unless hi=0 and
        // lo=0 (any negative end makes the range unreachable).
        if (hi != 0 || lo != 0) return true;
        return narrow(e->a, 0, 0, dom);
    }
    case NK::Shl: {
        if (auto c = asConst(e->b)) {
            const unsigned s = static_cast<unsigned>(*c) & 63;
            if (s == 0) return narrow(e->a, lo, hi, dom);
            if ((hi >> s) << s != hi || s >= 64) return true;
            const uint64_t nlo = (lo + (1ULL << s) - 1) >> s;
            return narrow(e->a, nlo, hi >> s, dom);
        }
        return true;
    }
    case NK::Shr: {
        if (auto c = asConst(e->b)) {
            const unsigned s = static_cast<unsigned>(*c) & 63;
            return narrow(e->a, lo << s, (hi << s) | ((1ULL << s) - 1), dom);
        }
        return true;
    }
    case NK::Extract: {
        const int s = e->aux * 8;
        if (s >= 64) return true;
        return narrow(e->a, static_cast<uint64_t>(lo) << s,
                      (static_cast<uint64_t>(hi) << s) |
                          ((s >= 64) ? 0 : ((1ULL << s) - 1)),
                      dom);
    }
    case NK::Cmp: {
        // Comparison values are 0/1.  Only "must be true" (lo >= 1) with a
        // useful predicate carries narrowing information.
        if (lo == 0 && hi >= 1) return true;
        if (lo >= 1) {
            Interval bi = ivEval(e->b, dom);
            switch (e->pred) {
            case Pred::Eq:
                return narrow(e->a, bi.lo, bi.hi, dom);
            case Pred::Ult:
            case Pred::Slt:
                if (bi.lo == bi.hi && bi.lo > 0)
                    return narrow(e->a, 0, bi.lo - 1, dom);
                return true;
            case Pred::Ule:
            case Pred::Sle:
                if (bi.lo == bi.hi)
                    return narrow(e->a, 0, bi.lo, dom);
                return true;
            default:
                return true;
            }
        }
        return true;  // comparison must be false: no sound narrowing
    }
    case NK::Piece:
        return true;  // decomposition not worth the precision here
    case NK::ITE:
    case NK::Carry:
    case NK::Borrow:
    case NK::Xor:
    case NK::Div:
    case NK::Rem:
    case NK::Sar:
        return true;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Constraints and solving
// ---------------------------------------------------------------------------

struct Constraint {
    Sym lhs;
    Pred pred;
    Sym rhs;
};

uint64_t halfOffset(int size) {
    const int bits = size * 8;
    return bits >= 64 ? (1ULL << 63) : (1ULL << (bits - 1));
}

// Does the constraint definitely hold over the domains?  1 yes, 0 no, -1 maybe
int constraintHolds(const Constraint& c, const Domains& dom) {
    const int size = c.lhs->size;
    Interval a = ivEval(c.lhs, dom), b = ivEval(c.rhs, dom);
    if (a.empty || b.empty) return 0;
    uint64_t alo = a.lo, ahi = a.hi, blo = b.lo, bhi = b.hi;
    Pred p = c.pred;
    // signed comparisons via the +2^(n-1) bijection
    if (p >= Pred::Slt) {
        const uint64_t h = halfOffset(size);
        alo = truncOf(alo + h, size); ahi = truncOf(ahi + h, size);
        blo = truncOf(blo + h, size); bhi = truncOf(bhi + h, size);
        if (alo > ahi || blo > bhi) return -1;
        p = static_cast<Pred>(static_cast<int>(p) - 4);
    }
    auto holds = [&](uint64_t x, uint64_t y) {
        switch (p) {
        case Pred::Eq: return x == y;
        case Pred::Ne: return x != y;
        case Pred::Ult: return x < y;
        case Pred::Ule: return x <= y;
        case Pred::Ugt: return x > y;
        case Pred::Uge: return x >= y;
        default: return false;
        }
    };
    if (holds(ahi, blo) && holds(alo, bhi)) {
        // all pairings agree only when intervals degenerate appropriately
        switch (p) {
        case Pred::Eq:
            if (alo == ahi && blo == bhi && alo == blo) return 1;
            return -1;
        case Pred::Ne:
            if (ahi < blo || bhi < alo) return 1;
            return -1;
        case Pred::Ult:
        case Pred::Ule:
            if (p == Pred::Ult ? ahi < blo : ahi <= blo) return 1;
            return -1;
        case Pred::Ugt:
        case Pred::Uge:
            if (p == Pred::Ugt ? alo > bhi : alo >= bhi) return 1;
            return -1;
        default: return -1;
        }
    }
    if (!holds(ahi, blo) && !holds(alo, bhi)) {
        // check whether any pairing could hold
        bool any = false;
        // conservative: extremes
        any |= holds(alo, blo) || holds(alo, bhi) || holds(ahi, blo) ||
               holds(ahi, bhi);
        if (!any) switch (p) {
            case Pred::Eq: any |= (alo <= bhi && blo <= ahi); break;
            case Pred::Ne: any |= true; break;
            case Pred::Ult:
            case Pred::Ule: any |= alo <= bhi; break;
            case Pred::Ugt:
            case Pred::Uge: any |= blo <= ahi; break;
            default: break;
            }
        return any ? -1 : 0;
    }
    return -1;
}

// Narrow domains with one constraint.  Returns false when infeasible.
bool narrowConstraint(const Constraint& c, Domains& dom) {
    // Comparison against a constant interval gets the projection treatment.
    Interval b = ivEval(c.rhs, dom);
    if (b.empty) return false;
    uint64_t lo = b.lo, hi = b.hi;
    Pred p = c.pred;
    if (p >= Pred::Slt) {
        // shift both sides; only sound for constant rhs handled here
        if (c.rhs->kind != NK::Const) return true;
        const uint64_t h = halfOffset(c.lhs->size);
        lo = truncOf(lo + h, c.lhs->size);
        hi = truncOf(hi + h, c.lhs->size);
        p = static_cast<Pred>(static_cast<int>(p) - 4);
    }
    switch (p) {
    case Pred::Eq:
        return narrow(c.lhs, lo, hi, dom);
    case Pred::Ne:
        if (lo == hi) {
            // lhs != const:  exclusion narrows interval-wise only at the
            // extremes; interior exclusions would need a domain split.
            Interval a = ivEval(c.lhs, dom);
            if (a.empty) return false;
            if (a.lo == a.hi) return a.lo != lo;
            const uint64_t m = maskOf(c.lhs->size);
            if (lo == 0) return narrow(c.lhs, 1, m, dom);
            if (lo == m) return narrow(c.lhs, 0, m - 1, dom);
        }
        return true;
    case Pred::Ult:
        if (lo == 0) return false;
        return narrow(c.lhs, 0, lo - 1, dom);
    case Pred::Ule:
        return narrow(c.lhs, 0, hi, dom);
    case Pred::Ugt:
        if (hi == maskOf(c.lhs->size)) return false;
        return narrow(c.lhs, hi + 1, maskOf(c.lhs->size), dom);
    case Pred::Uge:
        return narrow(c.lhs, lo, maskOf(c.lhs->size), dom);
    default:
        return true;
    }
}

uint64_t evalConcrete(const Sym& e, const std::vector<uint8_t>& inputBytes) {
    switch (e->kind) {
    case NK::Const: return e->value;
    case NK::Unknown: return 0;
    case NK::Input:
        return e->index < inputBytes.size() ? inputBytes[e->index] : 0;
    default: break;
    }
    const uint64_t m = maskOf(e->size);
    auto A = [&]() { return evalConcrete(e->a, inputBytes); };
    auto B = [&]() { return evalConcrete(e->b, inputBytes); };
    switch (e->kind) {
    case NK::Add: return (A() + B()) & m;
    case NK::Sub: return (A() - B()) & m;
    case NK::Mul: return (A() * B()) & m;
    case NK::Div: {
        const uint64_t d = B();
        return d ? A() / d : 0;
    }
    case NK::Rem: {
        const uint64_t d = B();
        return d ? A() % d : 0;
    }
    case NK::And: return A() & B();
    case NK::Or: return A() | B();
    case NK::Xor: return A() ^ B();
    case NK::Shl: return (A() << (B() & 63)) & m;
    case NK::Shr: return A() >> (B() & 63);
    case NK::Sar: {
        const int bits = e->size * 8;
        uint64_t s = A() & m;
        if (bits < 64 && (s >> (bits - 1)) & 1) s |= ~m;
        return (static_cast<int64_t>(s) >> (B() & 63)) & m;
    }
    case NK::Not: return ~A() & m;
    case NK::Neg: return (0 - A()) & m;
    case NK::Zext: return A() & m;
    case NK::Sext: {
        const int bits = e->a->size * 8;
        uint64_t s = A();
        if (bits < 64 && (s >> (bits - 1)) & 1) s |= ~maskOf(e->a->size);
        return s & m;
    }
    case NK::Piece: {
        const int shift = e->b->size * 8;
        return (A() << shift | B()) & m;
    }
    case NK::Extract:
        return (A() >> (e->aux * 8)) & m;
    case NK::Cmp:
        return evalCmp(e->pred, A(), B(), e->a->size);
    case NK::ITE:
        return A() ? B() : evalConcrete(e->c, inputBytes);
    case NK::Carry:
    case NK::Borrow:
        return 0;  // over-approximated; verified constraints decide
    }
    return 0;
}

bool satisfiesAll(const std::vector<Constraint>& cs,
                  const std::vector<uint8_t>& inputBytes) {
    for (const Constraint& c : cs) {
        const uint64_t a = evalConcrete(c.lhs, inputBytes) & maskOf(c.lhs->size);
        const uint64_t b = evalConcrete(c.rhs, inputBytes) & maskOf(c.rhs->size);
        if (!evalCmp(c.pred, a, b, c.lhs->size)) return false;
    }
    return true;
}

struct SolveResult {
    bool feasible = false;
    bool exact = false;  // false: underdetermined, no verified model
    std::vector<uint8_t> model;
};

// Compact expression tree dump for diagnostics.
std::string dumpExpr(const Sym& e) {
    if (!e) return "?";
    switch (e->kind) {
    case NK::Const: return "c" + std::to_string(e->value);
    case NK::Input: return "i" + std::to_string(e->index);
    case NK::Unknown: return "u";
    case NK::Zext: return "z(" + dumpExpr(e->a) + ")";
    case NK::Sext: return "s(" + dumpExpr(e->a) + ")";
    case NK::Not: return "~(" + dumpExpr(e->a) + ")";
    case NK::Neg: return "-(" + dumpExpr(e->a) + ")";
    case NK::Extract:
        return "x" + std::to_string(e->aux) + "(" + dumpExpr(e->a) + ")";
    default: break;
    }
    const char* k = "?";
    switch (e->kind) {
    case NK::Add: k = "+"; break;
    case NK::Sub: k = "-"; break;
    case NK::Mul: k = "*"; break;
    case NK::Div: k = "/"; break;
    case NK::Rem: k = "%"; break;
    case NK::And: k = "&"; break;
    case NK::Or: k = "|"; break;
    case NK::Xor: k = "^"; break;
    case NK::Shl: k = "<<"; break;
    case NK::Shr: k = ">>"; break;
    case NK::Sar: k = ">>s"; break;
    case NK::Piece: k = ":"; break;
    case NK::Cmp:
        return "(" + dumpExpr(e->a) + "==" + dumpExpr(e->b) + ")?1:0";
    default: break;
    }
    return "(" + dumpExpr(e->a) + k + dumpExpr(e->b) + ")";
}

SolveResult solveConstraints(const std::vector<Constraint>& cs,
                             uint32_t inputCount) {
    SolveResult out;
    const bool trace = std::getenv("SYMTRACE") != nullptr;
    if (trace)
        for (const Constraint& c : cs)
            std::fprintf(stderr, "[solve] constr %s pred=%d %s\n",
                         dumpExpr(c.lhs).c_str(), (int)c.pred,
                         dumpExpr(c.rhs).c_str());
    Domains dom;
    dom.byte.assign(inputCount, {0, 255});
    // Fixpoint narrowing.
    for (int round = 0; round < 128; ++round) {
        bool any = false;
        for (const Constraint& c : cs) {
            Domains before = dom;
            if (!narrowConstraint(c, dom))
                return out;  // infeasible
            for (size_t i = 0; i < dom.byte.size(); ++i)
                if (dom.byte[i] != before.byte[i]) any = true;
        }
        // definite-false detection
        for (const Constraint& c : cs)
            if (constraintHolds(c, dom) == 0) return out;
        if (!any) break;
    }
    if (trace) {
        std::string d;
        for (size_t i = 0; i < dom.byte.size(); ++i) {
            if (dom.byte[i].first == 0 && dom.byte[i].second == 255) continue;
            d += " [" + std::to_string(i) + "]=" +
                 std::to_string(dom.byte[i].first) + ".." +
                 std::to_string(dom.byte[i].second);
        }
        std::fprintf(stderr, "[solve] pinned:%s\n", d.c_str());
    }
    out.feasible = true;
    // All singletons -> candidate model, verified concretely.
    bool allSingle = true;
    for (const auto& d : dom.byte)
        if (d.first != d.second) allSingle = false;
    std::vector<uint8_t> model(inputCount, 0);
    for (size_t i = 0; i < dom.byte.size(); ++i)
        model[i] = static_cast<uint8_t>(dom.byte[i].first);
    if (allSingle && satisfiesAll(cs, model)) {
        out.exact = true;
        out.model = model;
        return out;
    }
    // Bounded enumeration over the remaining Cartesian product.
    uint64_t space = 1;
    for (const auto& d : dom.byte) {
        space *= (d.second - d.first + 1);
        if (space > (1ULL << 22)) break;  // cap early: 256^n wraps u64
    }
    if (space <= (1ULL << 22)) {
        std::vector<uint8_t> cand = model;
        for (;;) {
            if (satisfiesAll(cs, cand)) {
                out.exact = true;
                out.model = cand;
                return out;
            }
            size_t i = 0;
            for (; i < cand.size(); ++i) {
                if (++cand[i] <= dom.byte[i].second) break;
                cand[i] = static_cast<uint8_t>(dom.byte[i].first);
            }
            if (i == cand.size()) break;
        }
        return out;  // feasible but no model found (shouldn't happen)
    }
    // Undetermined free bytes: try the lower-bound model; constraints only
    // reference path-relevant inputs, so don't-care bytes verify trivially.
    if (satisfiesAll(cs, model)) {
        out.exact = true;
        out.model = model;
        return out;
    }
    out.feasible = true;  // underdetermined: too large to enumerate
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Symbolic execution state and interpreter
// ---------------------------------------------------------------------------

namespace {

struct SymState {
    uint64_t pc = 0;
    std::map<uint64_t, Sym> regs;  // register offset -> value
    std::map<uint64_t, Sym> mem;   // ram overlay: address -> byte value
    std::vector<Constraint> constraints;
    uint64_t steps = 0;
    uint32_t inputCount = 0;        // next fresh input byte index
    std::map<uint64_t, uint32_t> visits;
    std::vector<uint64_t> path;

    Sym getReg(uint64_t offset) const {
        const auto it = regs.find(offset);
        if (it != regs.end()) return it->second;
        return con(0, 8);
    }
    void setReg(uint64_t offset, Sym v) { regs[offset] = std::move(v); }
};

uint64_t spOffsetFor(const std::string& arch) {
    if (arch.rfind("x86", 0) == 0) return 4 * 8;
    if (arch == "aarch64" || arch == "arm64") return 31 * 8;
    return 2 * 8;
}

std::vector<uint64_t> argRegsFor(const std::string& arch,
                                 const std::string& format) {
    // PE images always use the Windows x64 calling convention regardless
    // of the architecture label.
    if (arch.rfind("x86", 0) == 0 &&
        (arch.find("win64") != std::string::npos ||
         format.rfind("PE", 0) == 0))
        return {1 * 8, 2 * 8, 8 * 8, 9 * 8};
    if (arch.rfind("x86", 0) == 0)
        return {7 * 8, 6 * 8, 2 * 8, 1 * 8, 8 * 8, 9 * 8};
    if (arch == "aarch64" || arch == "arm64")
        return {0, 8, 16, 24, 32, 40, 48, 56};
    std::vector<uint64_t> r;
    for (int i = 0; i < 8; ++i) r.push_back((10 + i) * 8);
    return r;
}

// Per-instruction operand resolution.
class InsnExec {
public:
    InsnExec(const PcodeInsn& insn, SymState& st,
             const std::function<bool(uint64_t, void*, size_t)>& imgRead)
        : insn_(insn), st_(st), imgRead_(imgRead) {}

    Sym valueOf(uint64_t id) {
        const Varnode* v = insn_.find(id);
        if (!v) return con(0, 8);
        switch (v->kind) {
        case Varnode::CONST: return con(v->offset, v->size);
        case Varnode::REGISTER: {
            Sym r = st_.getReg(v->offset);
            return resize(r, v->size);
        }
        case Varnode::UNIQUE: {
            const auto it = temps_.find(v->id);
            if (it != temps_.end()) return it->second;
            return con(0, v->size);
        }
        case Varnode::RAM: {
            const auto it = st_.mem.find(v->offset);
            if (it != st_.mem.end()) return resize(it->second, v->size);
            uint8_t b = 0;
            if (imgRead_(v->offset, &b, 1)) return con(b, v->size);
            return con(0, v->size);
        }
        }
        return con(0, v->size);
    }

    bool isSymbolic(uint64_t id) const {
        const Varnode* v = insn_.find(id);
        if (!v) return false;
        if (v->kind == Varnode::UNIQUE) {
            const auto it = temps_.find(v->id);
            return it != temps_.end() && !asConst(it->second);
        }
        if (v->kind == Varnode::REGISTER)
            return !asConst(st_.getReg(v->offset));
        return false;
    }

    void setOut(uint64_t id, Sym value) {
        if (!id) return;
        const Varnode* v = insn_.find(id);
        if (!v) return;
        if (v->kind == Varnode::REGISTER)
            st_.setReg(v->offset, resize(std::move(value), v->size));
        else
            temps_[v->id] = resize(std::move(value), v->size);
    }

    Sym resize(Sym s, int size) {
        if (!s) s = con(0, size);
        if (s->size == size) return s;
        if (auto v = asConst(s)) return con(*v, size);
        if (s->size > size) {
            // Little-endian truncation keeps the LOW `size` bytes.
            auto n = std::make_shared<Node>();
            n->kind = NK::Extract;
            n->size = size;
            n->aux = 0;
            n->a = s;
            return n;
        }
        return mkZext(s, size);
    }

    // Multi-byte little-endian read from state overlay then image.
    Sym readMem(uint64_t addr, int size) {
        auto byteAt = [&](uint64_t a) -> Sym {
            const auto it = st_.mem.find(a);
            if (it != st_.mem.end()) return resize(it->second, 1);
            uint8_t b = 0;
            imgRead_(a, &b, 1);
            return con(b, 1);
        };
        if (size <= 1) return byteAt(addr);
        Sym acc = byteAt(addr + static_cast<uint64_t>(size) - 1);
        for (int i = size - 2; i >= 0; --i)
            acc = mkPiece(acc, byteAt(addr + static_cast<uint64_t>(i)));
        return acc;
    }

    void writeMem(uint64_t addr, Sym value, int size) {
        for (int i = 0; i < size; ++i) {
            st_.mem[addr + static_cast<uint64_t>(i)] =
                resize(mkExtract(value, i), 1);
        }
    }

private:
    const PcodeInsn& insn_;
    SymState& st_;
    const std::function<bool(uint64_t, void*, size_t)>& imgRead_;
    std::map<uint64_t, Sym> temps_;
};

// Ops the executor implements natively.
bool isNative(POp op) {
    switch (op) {
    case POp::COPY:
    case POp::INT_ADD:
    case POp::INT_SUB:
    case POp::INT_MULT:
    case POp::INT_DIV:
    case POp::INT_SDIV:
    case POp::INT_REM:
    case POp::INT_SREM:
    case POp::INT_AND:
    case POp::INT_OR:
    case POp::INT_XOR:
    case POp::INT_NEGATE:
    case POp::INT_NOT:
    case POp::INT_LEFT:
    case POp::INT_RIGHT:
    case POp::INT_SRIGHT:
    case POp::INT_ZEXT:
    case POp::INT_SEXT:
    case POp::INT_EQUAL:
    case POp::INT_NOTEQUAL:
    case POp::INT_LESS:
    case POp::INT_SLESS:
    case POp::INT_LESSEQUAL:
    case POp::INT_SLESSEQUAL:
    case POp::BOOL_NEGATE:
    case POp::BOOL_XOR:
    case POp::BOOL_AND:
    case POp::BOOL_OR:
    case POp::PIECE:
    case POp::SUBPIECE:
    case POp::LOAD:
    case POp::STORE:
    case POp::BRANCH:
    case POp::CBRANCH:
    case POp::BRANCHIND:
    case POp::CALL:
    case POp::CALLIND:
    case POp::RETURN:
    case POp::SELECT:
        return true;
    default:
        return false;
    }
}

struct StepOutcome {
    std::vector<SymState> next;
    std::string prune;      // set when the state cannot continue
    bool reached = false;   // pc hit the target
};

class SymbolicReach {
public:
    SymbolicReach(const SleighEngine& engine, const Program& program,
                  ReachOptions options)
        : engine_(engine), prog_(program), opt_(std::move(options)),
          imgRead_([&](uint64_t a, void* b, size_t n) {
              return prog_.memory.read(a, b, n);
          }) {
        inputFactory_.concrete = opt_.concreteInput.empty()
                                     ? nullptr
                                     : &opt_.concreteInput;
    }

    ReachResult run() {
        ReachResult result;
        const bool explore = exploreMode_;
        // Symbol seeding ranges.
        std::vector<std::pair<uint64_t, uint64_t>> seedRanges =
            opt_.symbolicMemory;
        // Locate start: explicit, else the "main" symbol, else entry point.
        uint64_t start = opt_.startAddress;
        bool startIsMain = false;
        if (!start) {
            for (const Symbol& s : prog_.symbols)
                if (s.isFunction && s.name == "main") {
                    start = s.addr;
                    startIsMain = true;
                    break;
                }
            if (!start) start = prog_.entryPoint;
        }
        if (!start) {
            result.reason = "no entry point or start address";
            return result;
        }

        SymState initial;
        initial.pc = start;
        initial.inputCount = 0;
        const uint64_t spOff = spOffsetFor(prog_.arch);
        const uint64_t stackTop = 0x70000000ULL;
        initial.setReg(spOff, con(stackTop, 8));
        if (startIsMain) {
            // SysV/win64 both pass argc in the first integer arg register,
            // argv in the second.  Model argc=2, argv[1] = 32 symbolic
            // bytes (argv[0] = "prog").
            const std::vector<uint64_t> argRegs = argRegsFor(prog_.arch, prog_.format);
            const uint64_t argvBuf = stackTop - 0x4000;
            const uint64_t argStr = argvBuf + 0x1000;
            initial.setReg(argRegs.size() > 0 ? argRegs[0] : 0, con(2, 8));
            // write argv array + strings concretely
            auto put64 = [&](uint64_t addr, uint64_t v) {
                for (int i = 0; i < 8; ++i)
                    initial.mem[addr + i] = con((v >> (8 * i)) & 0xff, 1);
            };
            put64(argvBuf, argStr);
            put64(argvBuf + 8, argStr + 0x20);
            put64(argvBuf + 16, 0);
            const char* prog = "prog";
            for (int i = 0; i < 5; ++i)
                initial.mem[argStr + i] = con(prog[i], 1);
            // argv[1]: symbolic bytes
            for (int i = 0; i < 32; ++i) {
                const uint32_t idx = initial.inputCount++;
                initial.mem[argStr + 0x20 + i] = inputFactory_.make(idx);
            }
            if (argRegs.size() > 1)
                initial.setReg(argRegs[1], con(argvBuf, 8));
            if (argRegs.size() > 2)
                initial.setReg(argRegs[2], con(argvBuf + 16, 8));
        }
        // Seed symbolic memory ranges.
        for (const auto& range : seedRanges) {
            for (uint64_t i = 0; i < range.second; ++i) {
                const uint32_t idx = initial.inputCount++;
                initial.mem[range.first + i] = inputFactory_.make(idx);
            }
        }
        totalInputs_ = initial.inputCount;
        // stdin-modeled input bytes (from read/fgets/getchar hooks) are
        // allocated after this prefix; without the stdin model the payload
        // of interest starts at 0 (argv seed / --sym-mem ranges).
        const uint32_t stdinOffset = opt_.symbolicStdin ? initial.inputCount : 0;

        std::deque<SymState> queue;
        queue.push_back(std::move(initial));
        uint64_t explored = 0, pruned = 0;
        std::map<std::string, uint64_t> pruneReasons;

        while (!queue.empty()) {
            if (explored + queue.size() > opt_.maxStates * 4 &&
                queue.size() > opt_.maxStates) {
                result.reason = "state budget exhausted";
                break;
            }
            SymState st = std::move(queue.front());
            queue.pop_front();
            ++explored;
            const bool symTrace = std::getenv("SYMTRACE") != nullptr;
            if (symTrace)
                std::fprintf(stderr, "[sym] step pc=%llx steps=%llu constr=%zu\n",
                             (unsigned long long)st.pc,
                             (unsigned long long)st.steps,
                             st.constraints.size());
            StepOutcome outcome = step(std::move(st));
            if (symTrace)
                std::fprintf(stderr, "[sym]   -> next=%zu prune=%s\n",
                             outcome.next.size(), outcome.prune.c_str());
            if (outcome.reached && !explore) {
                SymState& winner = outcome.next.front();
                result.reached = true;
                result.reason = "found";
                result.steps = winner.steps;
                result.statesExplored = explored;
                result.statesPruned = pruned;
                if (opt_.trace) result.winningPath = winner.path;
                if (std::getenv("SYMTRACE"))
                    std::fprintf(stderr, "[sym] reached with %zu constraints\n",
                                 winner.constraints.size());
                result.stdinOffset = stdinOffset;
                if (!opt_.concreteInput.empty()) {
                    // Verification replay: reaching the target concretely
                    // is the only result that matters.
                    result.input = opt_.concreteInput;
                    return result;
                }
                auto solved =
                    solveConstraints(winner.constraints, totalInputs_);
                if (solved.exact) {
                    result.input = std::move(solved.model);
                } else {
                    result.reason = "found (constraints underdetermined; "
                                    "no verified model)";
                }
                return result;
            }
            for (SymState& ns : outcome.next)
                queue.push_back(std::move(ns));
            if (!outcome.prune.empty()) {
                ++pruned;
                ++pruneReasons[outcome.prune];
            }
            result.statesExplored = explored;
            result.statesPruned = pruned;
        }
        if (result.reason.empty()) {
            if (explore) {
                std::ostringstream why;
                why << "exploration complete (" << explored << " states explored, "
                    << pruned << " pruned)";
                result.reason = why.str();
            } else {
            std::ostringstream why;
            why << "target not reached (" << explored << " states explored)";
            if (!pruneReasons.empty()) {
                why << "; pruned:";
                for (const auto& kv : pruneReasons)
                    why << " " << kv.first << "=" << kv.second;
            }
            result.reason = why.str();
            }
        }
        result.steps = explored;
        return result;
    }

    // Exploration mode (exploreIndirectTargets): identical BFS to run(), but
    // never stops at a single target; instead every concretely-resolved
    // indirect call/branch site is accumulated in indirectSites_.
    IndirectExploreResult explore() {
        exploreMode_ = true;
        ReachResult r = run();
        IndirectExploreResult res;
        res.statesExplored = r.statesExplored;
        res.statesPruned = r.statesPruned;
        res.reason = r.reason;
        for (const auto& kv : indirectSites_) {
            IndirectSite site;
            site.addr = kv.first;
            const auto kind = siteIsCall_.find(kv.first);
            site.isCall = kind != siteIsCall_.end() && kind->second;
            site.targets.assign(kv.second.begin(), kv.second.end());
            res.sites.push_back(std::move(site));
        }
        std::sort(res.sites.begin(), res.sites.end(),
                  [](const IndirectSite& a, const IndirectSite& b) {
                      return a.addr < b.addr;
                  });
        return res;
    }

private:
    StepOutcome step(SymState st) {
        StepOutcome out;
        if (st.steps >= opt_.maxStepsPerState) {
            out.prune = "step-limit";
            return out;
        }
        // Fetch and lift.
        PcodeInsn insn;
        std::string err;
        if (!engine_.disassemble(imgRead_, st.pc, insn, err)) {
            out.prune = "undecodable-pc";
            return out;
        }
        const uint64_t curPc = st.pc;
        const uint32_t visits = ++st.visits[st.pc];
        if (visits > opt_.loopBound) {
            out.prune = "loop-bound";
            return out;
        }
        ++st.steps;
        if (opt_.trace && st.path.size() < 4096) st.path.push_back(st.pc);

        InsnExec ex(insn, st, imgRead_);
        if (std::getenv("SYMTRACE_OPS")) {
            std::fprintf(stderr, "[ops] pc=%llx:\n", (unsigned long long)st.pc);
            auto describe = [&](uint64_t id) -> std::string {
                const Varnode* v = insn.find(id);
                if (!v) return "-";
                std::string s = "k" + std::to_string((int)v->kind) + ":" +
                                std::to_string(v->size) + "B@" +
                                std::to_string(v->offset);
                return s;
            };
            for (const PcodeOp& op : insn.ops)
                std::fprintf(stderr, "    op=%d out=%llu(%s) in=%llu(%s),"
                                     "%llu(%s),%llu(%s)\n",
                             (int)op.op, (unsigned long long)op.out,
                             describe(op.out).c_str(),
                             (unsigned long long)op.in0,
                             describe(op.in0).c_str(),
                             (unsigned long long)op.in1,
                             describe(op.in1).c_str(),
                             (unsigned long long)op.in2,
                             describe(op.in2).c_str());
        }
        bool branchTaken = false;
        uint64_t branchTarget = 0;
        bool hasBranch = false;

        for (const PcodeOp& op : insn.ops) {
            if (op.op == POp::BRANCH || op.op == POp::CBRANCH ||
                op.op == POp::BRANCHIND || op.op == POp::CALL ||
                op.op == POp::CALLIND || op.op == POp::RETURN ||
                op.op == POp::LOAD || op.op == POp::STORE) {
                // handled below
            }
            switch (op.op) {
            case POp::COPY:
                ex.setOut(op.out, ex.valueOf(op.in0));
                break;
            case POp::INT_ADD:
                ex.setOut(op.out, mkAdd(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_SUB:
                ex.setOut(op.out, mkSub(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_MULT:
                ex.setOut(op.out, mkMul(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_DIV: {
                Sym r = mkDiv(ex.valueOf(op.in0), ex.valueOf(op.in1), false, false);
                if (!r) { out.prune = "div-by-symbolic-or-zero"; return out; }
                ex.setOut(op.out, r);
                break;
            }
            case POp::INT_SDIV: {
                Sym r = mkDiv(ex.valueOf(op.in0), ex.valueOf(op.in1), true, false);
                if (!r) { out.prune = "div-by-symbolic-or-zero"; return out; }
                ex.setOut(op.out, r);
                break;
            }
            case POp::INT_REM: {
                Sym r = mkDiv(ex.valueOf(op.in0), ex.valueOf(op.in1), false, true);
                if (!r) { out.prune = "div-by-symbolic-or-zero"; return out; }
                ex.setOut(op.out, r);
                break;
            }
            case POp::INT_SREM: {
                Sym r = mkDiv(ex.valueOf(op.in0), ex.valueOf(op.in1), true, true);
                if (!r) { out.prune = "div-by-symbolic-or-zero"; return out; }
                ex.setOut(op.out, r);
                break;
            }
            case POp::INT_AND:
                ex.setOut(op.out, mkAnd(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_OR:
                ex.setOut(op.out, mkOr(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_XOR:
                ex.setOut(op.out, mkXor(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_NEGATE:
                ex.setOut(op.out, mkNeg(ex.valueOf(op.in0)));
                break;
            case POp::INT_NOT:
                ex.setOut(op.out, mkNot(ex.valueOf(op.in0)));
                break;
            case POp::INT_LEFT:
                ex.setOut(op.out, mkShl(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_RIGHT:
                ex.setOut(op.out, mkShr(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_SRIGHT:
                ex.setOut(op.out, mkSar(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::INT_ZEXT:
                ex.setOut(op.out, mkZext(ex.valueOf(op.in0),
                                         insn.find(op.out)
                                             ? insn.find(op.out)->size
                                             : ex.valueOf(op.in0)->size + 1));
                break;
            case POp::INT_SEXT:
                ex.setOut(op.out, mkSext(ex.valueOf(op.in0),
                                         insn.find(op.out)
                                             ? insn.find(op.out)->size
                                             : ex.valueOf(op.in0)->size + 1));
                break;
            case POp::INT_EQUAL:
                ex.setOut(op.out, cmpNode(Pred::Eq, ex.valueOf(op.in0),
                                          ex.valueOf(op.in1)));
                break;
            case POp::INT_NOTEQUAL:
                ex.setOut(op.out, cmpNode(Pred::Ne, ex.valueOf(op.in0),
                                          ex.valueOf(op.in1)));
                break;
            case POp::INT_LESS:
                ex.setOut(op.out, cmpNode(Pred::Ult, ex.valueOf(op.in0),
                                          ex.valueOf(op.in1)));
                break;
            case POp::INT_SLESS:
                ex.setOut(op.out, cmpNode(Pred::Slt, ex.valueOf(op.in0),
                                          ex.valueOf(op.in1)));
                break;
            case POp::INT_LESSEQUAL:
                ex.setOut(op.out, cmpNode(Pred::Ule, ex.valueOf(op.in0),
                                          ex.valueOf(op.in1)));
                break;
            case POp::INT_SLESSEQUAL:
                ex.setOut(op.out, cmpNode(Pred::Sle, ex.valueOf(op.in0),
                                          ex.valueOf(op.in1)));
                break;
            case POp::BOOL_NEGATE:
                ex.setOut(op.out,
                          cmpNode(Pred::Eq, ex.valueOf(op.in0), con(0, 1)));
                break;
            case POp::BOOL_XOR:
                ex.setOut(op.out, mkXor(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::BOOL_AND:
                ex.setOut(op.out, mkAnd(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::BOOL_OR:
                ex.setOut(op.out, mkOr(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::PIECE:
                ex.setOut(op.out, mkPiece(ex.valueOf(op.in0), ex.valueOf(op.in1)));
                break;
            case POp::SUBPIECE: {
                const Varnode* off = insn.find(op.in1);
                const int shift = off ? static_cast<int>(off->offset) : 0;
                ex.setOut(op.out, mkExtract(ex.valueOf(op.in0), shift));
                break;
            }
            case POp::SELECT:
                ex.setOut(op.out,
                          node(NK::ITE, ex.valueOf(op.in0)->size == 1
                                            ? ex.valueOf(op.in1)->size
                                            : ex.valueOf(op.in0)->size,
                               ex.valueOf(op.in0), ex.valueOf(op.in1),
                               ex.valueOf(op.in2)));
                break;
            case POp::LOAD: {
                const Sym addr = ex.valueOf(op.in0);
                const Varnode* outV = insn.find(op.out);
                const int size = outV ? outV->size : 8;
                if (auto a = asConst(addr)) {
                    if (std::getenv("SYMTRACE")) {
                        const auto it = st.mem.find(*a);
                        std::fprintf(stderr, "[sym]   LOAD pc=%llx addr=%llx size=%d"
                                             " overlay=%s\n",
                                     (unsigned long long)st.pc,
                                     (unsigned long long)*a, size,
                                     it == st.mem.end() ? "miss"
                                     : (asConst(it->second) ? "const" : "SYMBOLIC"));
                    }
                    ex.setOut(op.out, ex.readMem(*a, size));
                } else {
                    out.prune = "symbolic-address-load";
                    return out;
                }
                break;
            }
            case POp::STORE: {
                const Sym addr = ex.valueOf(op.in0);
                const Varnode* valV = insn.find(op.in2);
                const int size = valV ? valV->size : 8;
                if (auto a = asConst(addr)) {
                    if (std::getenv("SYMTRACE") && *a >= 0x6fffffa0 &&
                        *a < 0x6fffffc0)
                        std::fprintf(stderr, "[sym]   STORE pc=%llx addr=%llx\n",
                                     (unsigned long long)st.pc,
                                     (unsigned long long)*a);
                    ex.writeMem(*a, ex.valueOf(op.in2), size);
                } else {
                    out.prune = "symbolic-address-store";
                    return out;
                }
                break;
            }
            case POp::BRANCH: {
                const Sym t = ex.valueOf(op.in0);
                if (auto v = asConst(t)) {
                    branchTaken = true;
                    hasBranch = true;
                    branchTarget = *v;
                } else {
                    out.prune = "symbolic-branch-target";
                    return out;
                }
                break;
            }
            case POp::CBRANCH: {
                // Operand order matches the concrete evaluator:
                // in0 = destination, in1 = condition.
                const Sym cond = ex.valueOf(op.in1);
                const Varnode* dv = insn.find(op.in0);
                if (std::getenv("SYMTRACE")) {
                    const Varnode* cv = insn.find(op.in1);
                    std::fprintf(stderr, "[sym]   CBRANCH pc=%llx cond=%d size=%d const=%d"
                                        " vnode k%d@%llu\n",
                                 (unsigned long long)st.pc, (int)cond->kind,
                                 cond->size, asConst(cond) ? 1 : 0,
                                 cv ? (int)cv->kind : -1,
                                 cv ? (unsigned long long)cv->offset : 0);
                }
                if (auto c = asConst(cond)) {
                    if (*c != 0 && dv && dv->kind == Varnode::CONST) {
                        branchTaken = true;
                        hasBranch = true;
                        branchTarget = dv->offset;
                    }
                } else if (dv && dv->kind == Varnode::CONST) {
                    // Fork on the symbolic condition.
                    SymState taken = st;
                    taken.constraints = st.constraints;
                    taken.path = st.path;
                    SymState notTaken = st;
                    notTaken.constraints = st.constraints;
                    notTaken.path = st.path;
                    Constraint tc{cond, Pred::Ne, con(0, cond->size)};
                    Constraint fc{cond, Pred::Eq, con(0, cond->size)};
                    // Normalize comparison conditions to predicate form.
                    if (cond->kind == NK::Cmp) {
                        tc = Constraint{cond->a, cond->pred, cond->b};
                        fc = Constraint{cond->a, complement(cond->pred),
                                        cond->b};
                    }
                    taken.constraints.push_back(tc);
                    notTaken.constraints.push_back(fc);
                    taken.pc = dv->offset;
                    notTaken.pc = insn.nextAddr;
                    out.next.push_back(std::move(taken));
                    out.next.push_back(std::move(notTaken));
                    hasBranch = false;  // successors already queued
                    branchTaken = false;
                    // signal early exit
                    out.next.shrink_to_fit();
                    return finishFork(std::move(out), insn);
                } else {
                    out.prune = "symbolic-branch-target";
                    return out;
                }
                break;
            }
            case POp::BRANCHIND: {
                const Sym t = ex.valueOf(op.in0);
                if (auto v = asConst(t)) {
                    indirectSites_[curPc].insert(*v);
                    siteIsCall_.emplace(curPc, false);
                    branchTaken = true;
                    hasBranch = true;
                    branchTarget = *v;
                } else {
                    out.prune = "indirect-branch";
                    return out;
                }
                break;
            }
            case POp::CALL: {
                const Varnode* tv = insn.find(op.in0);
                if (tv && tv->kind == Varnode::CONST) {
                    if (handleLibcCall(tv->offset, st, insn, out)) {
                        st.pc = insn.nextAddr;
                        return finishFork(std::move(out), insn);
                    }
                    if (!pushReturnAddress(st, insn)) {
                        out.prune = "symbolic-stack";
                        return out;
                    }
                    if (std::getenv("SYMTRACE"))
                        std::fprintf(stderr, "[sym]   CALL -> %llx\n",
                                     (unsigned long long)tv->offset);
                    branchTaken = true;
                    hasBranch = true;
                    branchTarget = tv->offset;
                } else {
                    out.prune = "indirect-call-target";
                    return out;
                }
                break;
            }
            case POp::CALLIND: {
                const Sym t = ex.valueOf(op.in0);
                if (auto v = asConst(t)) {
                    indirectSites_[curPc].insert(*v);
                    siteIsCall_.emplace(curPc, true);
                    if (handleLibcCall(*v, st, insn, out)) {
                        st.pc = insn.nextAddr;
                        return finishFork(std::move(out), insn);
                    }
                    if (!pushReturnAddress(st, insn)) {
                        out.prune = "symbolic-stack";
                        return out;
                    }
                    branchTaken = true;
                    hasBranch = true;
                    branchTarget = *v;
                } else {
                    out.prune = "indirect-call";
                    return out;
                }
                break;
            }
            case POp::RETURN: {
                // The simplified slaspec lowers `ret` to a bare `return`
                // (no pop), so model the architectural pop here to match
                // the push we emulate on CALL.
                const uint64_t spOffR = spOffsetFor(prog_.arch);
                auto rspR = asConst(st.getReg(spOffR));
                if (!rspR) { out.prune = "symbolic-stack"; return out; }
                const Sym t = ex.readMem(*rspR, 8);
                if (std::getenv("SYMTRACE"))
                    std::fprintf(stderr, "[sym]   ret rsp=%llx mem=%02x %02x %02x %02x\n",
                                 (unsigned long long)*rspR,
                                 (unsigned)(asConst(st.mem[*rspR])
                                                ? *asConst(st.mem[*rspR]) : 0xff),
                                 (unsigned)(asConst(st.mem[*rspR + 1])
                                                ? *asConst(st.mem[*rspR + 1]) : 0xff),
                                 (unsigned)(asConst(st.mem[*rspR + 2])
                                                ? *asConst(st.mem[*rspR + 2]) : 0xff),
                                 (unsigned)(asConst(st.mem[*rspR + 3])
                                                ? *asConst(st.mem[*rspR + 3]) : 0xff));
                st.setReg(spOffR, con(*rspR + 8, 8));
                if (auto v = asConst(t)) {
                    if (*v == 0) { out.prune = "returned"; return out; }
                    branchTaken = true;
                    hasBranch = true;
                    branchTarget = *v;
                } else {
                    out.prune = "symbolic-return";
                    return out;
                }
                break;
            }
            case POp::TRAP:
            case POp::SYSCALL:
            case POp::X86_STRING:
            case POp::X86_SYSTEM:
            case POp::X86_DIVIDE:
                out.prune = "unsupported-op";
                return out;
            case POp::MEMORY_BARRIER:
            case POp::CACHE_HINT:
            case POp::UNIMPLEMENTED:
                if (op.op == POp::UNIMPLEMENTED) {
                    out.prune = "unimplemented-op";
                    return out;
                }
                break;  // barriers/hints: no effect
            default:
                if (!isNative(op.op)) {
                    // Unsupported computational op (parity/carry/SIMD/float
                    // etc.): when fully concrete, replay via the pcode
                    // evaluator; otherwise produce an unconstrained
                    // "unknown" value so the path stays alive.  Control,
                    // memory and trap ops never reach here (handled or
                    // pruned above).
                    bool anySymbolic = false;
                    for (uint64_t id : {op.in0, op.in1, op.in2})
                        if (id && ex.isSymbolic(id)) anySymbolic = true;
                    if (anySymbolic) {
                        const Varnode* ov = insn.find(op.out);
                        ex.setOut(op.out,
                                  unknownSym(ov ? ov->size : 8));
                        break;
                    }
                    if (!evalConcreteFallback(insn, st)) {
                        out.prune = "unsupported-op";
                        return out;
                    }
                    // The fallback re-executed the whole instruction
                    // concretely; nothing more to do for this instruction.
                    st.pc = insn.nextAddr;
                    out.next.push_back(std::move(st));
                    return finishFork(std::move(out), insn);
                }
                break;
            }
            (void)branchTaken;
        }

        st.pc = hasBranch ? branchTarget : insn.nextAddr;
        out.next.push_back(std::move(st));
        return finishFork(std::move(out), insn);
    }

    StepOutcome finishFork(StepOutcome out, const PcodeInsn& insn) {
        // Target check for all queued successors.
        for (auto it = out.next.begin(); it != out.next.end();) {
            if (it->pc == opt_.targetAddress) {
                StepOutcome hit;
                hit.reached = true;
                hit.next.push_back(std::move(*it));
                return hit;
            }
            ++it;
        }
        (void)insn;
        return out;
    }

    // The x86-64 slaspec models CALL as a bare jump (no return-address
    // store), so emulate the architectural push here.  The matching `ret`
    // pops via its own LOAD/INT_ADD pcode.
    bool pushReturnAddress(SymState& st, const PcodeInsn& insn) {
        const uint64_t spOff = spOffsetFor(prog_.arch);
        auto rsp = asConst(st.getReg(spOff));
        if (!rsp) return false;
        for (int i = 0; i < 8; ++i)
            st.mem[*rsp - 8 + i] = con((insn.nextAddr >> (8 * i)) & 0xff, 1);
        if (std::getenv("SYMTRACE"))
            std::fprintf(stderr, "[sym]   push retaddr=%llx at sp=%llx\n",
                         (unsigned long long)insn.nextAddr,
                         (unsigned long long)(*rsp - 8));
        st.setReg(spOff, con(*rsp - 8, 8));
        return true;
    }

    // strcmp(p0, p1): fork into the equal state plus one state per first
    // differing position, so every path constraint stays conjunctive and
    // byte-precise.  p1 must be a concrete C string; p0 may point at
    // symbolic bytes.
    bool handleStrcmp(SymState& st, const PcodeInsn& insn, StepOutcome& out,
                      bool isStrncmp) {
        const std::vector<uint64_t> argRegs = argRegsFor(prog_.arch, prog_.format);
        auto regArg = [&](int n) -> Sym {
            if (n < static_cast<int>(argRegs.size()))
                return st.getReg(argRegs[n]);
            return con(0, 8);
        };
        const auto p0 = asConst(regArg(0));
        const auto p1 = asConst(regArg(1));
        if (!p0 || !p1) return false;
        // Read the concrete string at p1 from the image.
        std::vector<uint8_t> s;
        for (int i = 0; i < 64; ++i) {
            uint8_t b = 0;
            if (!imgRead_(*p1 + static_cast<uint64_t>(i), &b, 1)) break;
            if (b == 0) break;
            s.push_back(b);
        }
        if (s.empty()) return false;
        InsnExec ex(insn, st, imgRead_);
        auto byteAt = [&](uint64_t a) -> Sym {
            return ex.readMem(a, 1);
        };
        // Equal state: every byte matches and p0 terminates.
        {
            SymState eq = st;
            bool impossible = false;
            for (size_t i = 0; i < s.size(); ++i) {
                Sym b = byteAt(*p0 + i);
                if (auto v = asConst(b)) {
                    if (*v != s[i]) { impossible = true; break; }
                } else {
                    eq.constraints.push_back(Constraint{b, Pred::Eq,
                                                        con(s[i], 1)});
                }
            }
            Sym nul = byteAt(*p0 + s.size());
            if (!impossible) {
                if (auto v = asConst(nul)) {
                    if (*v != 0) impossible = true;
                } else {
                    eq.constraints.push_back(Constraint{nul, Pred::Eq,
                                                        con(0, 1)});
                }
            }
            if (!impossible) {
                eq.setReg(0, con(0, 8));
                eq.pc = insn.nextAddr;
                out.next.push_back(std::move(eq));
            }
        }
        // Not-equal states: first difference at position j.
        for (size_t j = 0; j <= s.size(); ++j) {
            const uint8_t expect = j < s.size() ? s[j] : 0;
            SymState ne = st;
            bool impossible = false;
            for (size_t i = 0; i < j; ++i) {
                Sym b = byteAt(*p0 + i);
                if (auto v = asConst(b)) {
                    if (*v != s[i]) { impossible = true; break; }
                } else {
                    ne.constraints.push_back(Constraint{b, Pred::Eq,
                                                        con(s[i], 1)});
                }
            }
            if (impossible) continue;
            Sym bj = byteAt(*p0 + j);
            if (auto v = asConst(bj)) {
                if (*v == expect) continue;
                ne.setReg(0, con(*v < expect ? 0xFFFFFFFFFFFFFFFFULL : 1, 8));
            } else {
                ne.constraints.push_back(Constraint{bj, Pred::Ne,
                                                    con(expect, 1)});
                // Sign of the (unknown) difference, for callers that test <0.
                Sym lt = cmpNode(Pred::Ult, bj, con(expect, 1));
                ne.setReg(0, node(NK::ITE, 8, lt,
                                  con(0xFFFFFFFFFFFFFFFFULL, 8), con(1, 8)));
            }
            ne.pc = insn.nextAddr;
            out.next.push_back(std::move(ne));
        }
        return true;
    }

    // Model a small set of libc entry points; returns true when handled.
    bool handleLibcCall(uint64_t target, SymState& st, const PcodeInsn& insn,
                        StepOutcome& out) {
        const Symbol* sym = nullptr;
        for (const Symbol& s : prog_.symbols)
            if (s.isFunction && s.addr == target) { sym = &s; break; }
        if (!sym) return false;
        // Bound PE imports are named "library!func"; hooks match the bare
        // function name.
        std::string name = sym->name;
        const size_t bang = name.find('!');
        if (bang != std::string::npos) name = name.substr(bang + 1);
        const uint64_t spOff = spOffsetFor(prog_.arch);
        auto rspc = asConst(st.getReg(spOff));
        if (!rspc) return false;
        const uint64_t rsp = *rspc;
        auto stackArg = [&](int n) -> std::optional<uint64_t> {
            uint8_t bytes[8] = {0};
            if (!imgRead_(rsp + 8 + 8 * n, bytes, 8)) {
                // overlay
                bool ok = true;
                for (int i = 0; i < 8; ++i) {
                    const auto it = st.mem.find(rsp + 8 + 8 * n + i);
                    if (it != st.mem.end()) {
                        if (auto v = asConst(it->second))
                            bytes[i] = static_cast<uint8_t>(*v);
                        else ok = false;
                    } else ok = false;
                }
                if (!ok) return std::nullopt;
            }
            uint64_t v = 0;
            std::memcpy(&v, bytes, 8);
            return v;
        };
        const std::vector<uint64_t> argRegs = argRegsFor(prog_.arch, prog_.format);
        auto regArg = [&](int n) -> Sym {
            if (n < static_cast<int>(argRegs.size()))
                return st.getReg(argRegs[n]);
            return con(0, 8);
        };
        const uint64_t retOff = 0;  // rax

        auto retConcrete = [&](uint64_t v) {
            st.setReg(retOff, con(v, 8));
            st.pc = insn.nextAddr;
            out.next.push_back(std::move(st));
        };

        if (name == "read" || name == "_read") {
            // read(fd, buf, n): model fd==0 as stdin of symbolic bytes.
            const auto fd = asConst(regArg(0));
            const auto buf = asConst(regArg(1));
            const auto n = asConst(regArg(2));
            if (!fd || !buf || !n) {
                if (std::getenv("SYMTRACE")) {
                    auto pr = [](const Sym& s, const char* nm) {
                        std::fprintf(stderr, " %s=%d", nm,
                                     s ? (int)s->kind : -1);
                    };
                    std::fprintf(stderr, "[sym]   read hook: non-const args");
                    pr(regArg(0), "fd"); pr(regArg(1), "buf");
                    pr(regArg(2), "n");
                    std::fprintf(stderr, "\n");
                }
                return false;
            }
            if (*fd != 0 || !opt_.symbolicStdin) {
                if (std::getenv("SYMTRACE"))
                    std::fprintf(stderr, "[sym]   read hook: fd=%llu stdin=%d\n",
                                 (unsigned long long)*fd,
                                 (int)opt_.symbolicStdin);
                return false;
            }
            const uint64_t len = std::min<uint64_t>(*n, opt_.stdinLength);
            InsnExec ex(insn, st, imgRead_);
            for (uint64_t i = 0; i < len; ++i) {
                const uint32_t idx = totalInputs_++;
                ex.writeMem(*buf + i, inputFactory_.make(idx), 1);
            }
            if (std::getenv("SYMTRACE"))
                std::fprintf(stderr, "[sym]   read hook: fd=%llu buf=%llx n=%llu"
                                     " -> %llu symbolic bytes\n",
                             (unsigned long long)*fd,
                             (unsigned long long)*buf,
                             (unsigned long long)*n,
                             (unsigned long long)len);
            retConcrete(len);
            return true;
        }
        if (name == "fgets" || name == "_fgets" || name == "gets" ||
            name == "_gets") {
            // fgets(buf, n, stream): deliver symbolic bytes + NUL.
            const auto buf = asConst(regArg(0));
            auto n = asConst(regArg(1));
            if (!buf) return false;
            if (name == "gets" || name == "_gets")
                n = static_cast<uint64_t>(opt_.stdinLength);
            if (!n) return false;
            if (!opt_.symbolicStdin) return false;
            const uint64_t len =
                std::min<uint64_t>(std::max<uint64_t>(1, *n) - 1,
                                   opt_.stdinLength);
            InsnExec ex(insn, st, imgRead_);
            for (uint64_t i = 0; i < len; ++i) {
                const uint32_t idx = totalInputs_++;
                ex.writeMem(*buf + i, inputFactory_.make(idx), 1);
            }
            ex.writeMem(*buf + len, con(0, 1), 1);
            retConcrete(*buf);
            return true;
        }
        if (name == "strcmp" || name == "_strcmp" || name == "strncmp" ||
            name == "_strncmp") {
            return handleStrcmp(st, insn, out, name == "strncmp" ||
                                           name == "_strncmp");
        }
        if (name == "getchar" || name == "_getchar") {
            if (!opt_.symbolicStdin) return false;
            const uint32_t idx = totalInputs_++;
            st.setReg(retOff, mkZext(inputFactory_.make(idx), 8));
            st.pc = insn.nextAddr;
            out.next.push_back(std::move(st));
            return true;
        }
        return false;
    }

    // Re-execute an instruction concretely via PcodeEvaluator.  All
    // referenced register/unique values must already be concrete.
    bool evalConcreteFallback(const PcodeInsn& insn, SymState& st) {
        PcodeEvaluator ev(insn);
        std::set<uint64_t> regIds, ramAddrs;
        for (const auto& kv : insn.varnodes) {
            const Varnode& v = kv.second;
            if (v.kind == Varnode::REGISTER) regIds.insert(v.offset);
        }
        for (uint64_t off : regIds) {
            Sym s = st.getReg(off);
            if (!s) s = con(0, 8);
            if (s->size <= 8) {
                ev.regs[off] = s->value;
            } else {
                std::vector<uint8_t> bytes(s->size, 0);
                for (int i = 0; i < s->size; ++i)
                    bytes[i] = static_cast<uint8_t>(s->value >> (8 * (i & 7)));
                ev.wideRegs[off] = std::move(bytes);
            }
        }
        // Seed flag registers to zero.
        for (uint64_t f = 4096; f < 4102; ++f)
            if (!ev.regs.count(f)) ev.regs[f] = 0;
        ev.run();
        if (ev.fault) return false;
        for (uint64_t off : regIds) {
            if (ev.wideRegs.count(off)) {
                const auto& bytes = ev.wideRegs[off];
                uint64_t v = 0;
                for (size_t i = 0; i < bytes.size() && i < 8; ++i)
                    v |= static_cast<uint64_t>(bytes[i]) << (8 * i);
                st.setReg(off, con(v, static_cast<int>(bytes.size())));
            } else {
                const auto it = ev.regs.find(off);
                if (it != ev.regs.end()) st.setReg(off, con(it->second, 8));
            }
        }
        // Rare: concrete branch side effects inside the fallback.
        if (ev.lastBranchTarget() && ev.branchTaken()) {
            st.pc = *ev.lastBranchTarget();
        }
        return true;
    }

    const SleighEngine& engine_;
    const Program& prog_;
    ReachOptions opt_;
    std::function<bool(uint64_t, void*, size_t)> imgRead_;
    InputFactory inputFactory_;
    uint32_t totalInputs_ = 0;
    // Exploration-mode accumulation: site pc -> concrete targets observed.
    std::map<uint64_t, std::set<uint64_t>> indirectSites_;
    std::map<uint64_t, bool> siteIsCall_;  // site pc -> true for CALLIND
    bool exploreMode_ = false;
};

} // namespace

ReachResult reachTarget(const SleighEngine& engine, const Program& program,
                        const ReachOptions& options) {
    SymbolicReach runner(engine, program, options);
    return runner.run();
}

IndirectExploreResult exploreIndirectTargets(const SleighEngine& engine,
                                             const Program& program,
                                             const ReachOptions& options) {
    SymbolicReach runner(engine, program, options);
    return runner.explore();
}

} // namespace centrifuge
