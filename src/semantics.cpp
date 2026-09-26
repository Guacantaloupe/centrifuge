// Semantic equivalence engine: canonical simplifier + bit-blast ANF prover.
// See semantics.hpp for the design notes.
#include "centrifuge/semantics.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>

namespace centrifuge {

Semantics::Semantics() {
    // Reserve id 0 as "no child": child fields use 0 = none, so real nodes
    // must start at id 1.
    nodes_.emplace_back();
}

bool Semantics::NodeKeyLess::operator()(const Node& x, const Node& y) const {
    if (x.kind != y.kind) return x.kind < y.kind;
    if (x.width != y.width) return x.width < y.width;
    if (x.constant != y.constant) return x.constant < y.constant;
    if (x.varId != y.varId) return x.varId < y.varId;
    if (x.a != y.a) return x.a < y.a;
    if (x.b != y.b) return x.b < y.b;
    if (x.c != y.c) return x.c < y.c;
    return x.aux < y.aux;
}

uint64_t Semantics::mask(uint8_t width) const {
    if (width >= 8) return ~0ULL;
    return (1ULL << (width * 8)) - 1;
}

uint32_t Semantics::mk(Node node) {
    const auto found = intern_.find(node);
    if (found != intern_.end()) return found->second;
    const uint32_t id = static_cast<uint32_t>(nodes_.size());
    nodes_.push_back(node);
    intern_.emplace(nodes_.back(), id);
    return id;
}

uint32_t Semantics::constant(uint8_t width, uint64_t value) {
    Node n;
    n.kind = Const;
    n.width = width;
    n.constant = value & mask(width);
    return mk(n);
}

uint32_t Semantics::variable(uint8_t width, uint64_t varId) {
    Node n;
    n.kind = Var;
    n.width = width;
    n.varId = varId;
    return mk(n);
}

uint32_t Semantics::unary(Kind kind, uint8_t width, uint32_t a) {
    Node n;
    n.kind = kind;
    n.width = width;
    n.a = a;
    return mk(n);
}

uint32_t Semantics::binary(Kind kind, uint8_t width, uint32_t a, uint32_t b) {
    Node n;
    n.kind = kind;
    n.width = width;
    n.a = a;
    n.b = b;
    return mk(n);
}

uint32_t Semantics::slice(uint8_t width, uint32_t a, uint64_t byteOffset) {
    Node n;
    n.kind = Slice;
    n.width = width;
    n.a = a;
    n.aux = byteOffset;
    return mk(n);
}

uint32_t Semantics::ite(uint8_t width, uint32_t c, uint32_t t, uint32_t e) {
    Node n;
    n.kind = Ite;
    n.width = width;
    n.a = c;
    n.b = t;
    n.c = e;
    return mk(n);
}

// ---------------------------------------------------------------------------
// Canonical simplifier
// ---------------------------------------------------------------------------

// Flatten `id` (interpreted as a `width`-byte value) into the linear form
// `out`.  Always succeeds: subtrees that are not affine (Xor/And/UDiv/...)
// become single opaque terms keyed by their node id.  Callers must
// canonicalize children first (canon does) so equal subterms share a key;
// that is what lets fromLinear pair Xor(a,b) with And(a,b) for the MBA
// template collapse.
bool Semantics::asLinear(uint32_t id, uint8_t width, Linear& out, int depth) {
    if (depth > 24) {
        out.terms[id] += 1;
        return true;
    }
    const Node& n = nodes_[id];
    const uint64_t wmask = mask(width);
    switch (n.kind) {
    case Const:
        out.constant = (out.constant + n.constant) & wmask;
        return true;
    case Var:
        out.terms[id] += 1;
        return true;
    case Add:
    case Sub: {
        const int sign = n.kind == Add ? 1 : -1;
        Linear right;
        asLinear(n.a, width, out, depth + 1);
        asLinear(n.b, width, right, depth + 1);
        for (const auto& [term, coeff] : right.terms) {
            const int64_t merged =
                static_cast<int64_t>(out.terms[term]) + sign * coeff;
            if (merged) out.terms[term] = merged;
            else out.terms.erase(term);
        }
        out.constant =
            (out.constant + (sign > 0 ? right.constant
                                      : (wmask + 1 - right.constant))) &
            wmask;
        return true;
    }
    case Neg: {
        Linear inner;
        asLinear(n.a, width, inner, depth + 1);
        for (const auto& [term, coeff] : inner.terms) {
            const int64_t merged =
                static_cast<int64_t>(out.terms[term]) - coeff;
            if (merged) out.terms[term] = merged;
            else out.terms.erase(term);
        }
        out.constant = (out.constant + (wmask + 1 - inner.constant)) & wmask;
        return true;
    }
    case Mul: {
        const Node& lhs = nodes_[n.a];
        const Node& rhs = nodes_[n.b];
        // Distribute only when one side is a plain constant scalar;
        // otherwise the whole product is one opaque term.
        uint64_t scalar = 0;
        uint32_t other = 0;
        if (lhs.kind == Const && rhs.kind != Const) {
            scalar = lhs.constant;
            other = n.b;
        } else if (rhs.kind == Const && lhs.kind != Const) {
            scalar = rhs.constant;
            other = n.a;
        } else {
            out.terms[id] += 1;
            return true;
        }
        Linear inner;
        asLinear(other, width, inner, depth + 1);
        // Scalar multiplication over the ring mod 2^(8w).
        for (const auto& [term, coeff] : inner.terms) {
            const uint64_t scaled =
                (static_cast<uint64_t>(coeff) * scalar) & wmask;
            const int64_t signedScaled =
                scaled <= wmask / 2
                    ? static_cast<int64_t>(scaled)
                    : static_cast<int64_t>(scaled) -
                          static_cast<int64_t>(wmask + 1);
            const int64_t merged =
                static_cast<int64_t>(out.terms[term]) + signedScaled;
            if (merged) out.terms[term] = merged;
            else out.terms.erase(term);
        }
        out.constant = (out.constant + inner.constant * scalar) & wmask;
        return true;
    }
    case Shl: {
        const Node& rhs = nodes_[n.b];
        if (rhs.kind != Const) {
            out.terms[id] += 1;
            return true;
        }
        const uint64_t bits = rhs.constant;
        const uint64_t factor = bits >= 64 ? 0 : (1ULL << bits) & wmask;
        Linear inner;
        asLinear(n.a, width, inner, depth + 1);
        for (const auto& [term, coeff] : inner.terms) {
            const uint64_t scaled =
                (static_cast<uint64_t>(coeff) * factor) & wmask;
            const int64_t signedScaled =
                scaled <= wmask / 2
                    ? static_cast<int64_t>(scaled)
                    : static_cast<int64_t>(scaled) -
                          static_cast<int64_t>(wmask + 1);
            const int64_t merged =
                static_cast<int64_t>(out.terms[term]) + signedScaled;
            if (merged) out.terms[term] = merged;
            else out.terms.erase(term);
        }
        out.constant = (out.constant + inner.constant * factor) & wmask;
        return true;
    }
    case Slice: {
        if (n.aux != 0) {
            // Non-zero offset: carries from dropped low bits cross into the
            // kept window, so truncation does not distribute.  Opaque term.
            out.terms[id] += 1;
            return true;
        }
        // Pure truncation distributes: parse the operand at the slice width.
        Linear inner;
        asLinear(n.a, n.width, inner, depth + 1);
        for (const auto& [term, coeff] : inner.terms) {
            const int64_t merged =
                static_cast<int64_t>(out.terms[term]) + coeff;
            if (merged) out.terms[term] = merged;
            else out.terms.erase(term);
        }
        out.constant = (out.constant + inner.constant) & wmask;
        return true;
    }
    case ZExt: {
        // Zero-extension: parse the operand at its own (narrower) width so
        // coefficients stay small non-negative residues, then merge.
        Linear inner;
        asLinear(n.a, nodes_[n.a].width, inner, depth + 1);
        for (const auto& [term, coeff] : inner.terms) {
            const int64_t merged =
                static_cast<int64_t>(out.terms[term]) + coeff;
            if (merged) out.terms[term] = merged;
            else out.terms.erase(term);
        }
        out.constant = (out.constant + inner.constant) & wmask;
        return true;
    }
    default:
        // Nonlinear subtree: one opaque term.
        out.terms[id] += 1;
        return true;
    }
}

uint32_t Semantics::fromLinear(const Linear& lin, uint8_t width) {
    // MBA template pair: 1*Xor(a,b) + 2*And(a,b) == Add(a,b)  (mod 2^(8w)).
    // Generalized to coefficient c and 2c.  Merge those term pairs first.
    // Iterate over a snapshot but always re-check the live coefficient in
    // `out.terms` so a term already consumed by an earlier merge is skipped.
    Linear out = lin;
    for (const auto& [term, coeff] : lin.terms) {
        if (coeff <= 0) continue;
        const Node& tn = nodes_[term];
        if (tn.kind != Xor) continue;
        // Look for And(a,b) or And(b,a) with coefficient 2*coeff.
        for (const auto& [term2, coeff2] : lin.terms) {
            if (coeff2 != 2 * coeff) continue;
            const Node& tn2 = nodes_[term2];
            if (tn2.kind != And) continue;
            const bool same = (tn2.a == tn.a && tn2.b == tn.b) ||
                              (tn2.a == tn.b && tn2.b == tn.a);
            if (!same) continue;
            // Both terms must still be fully present in `out` (an earlier
            // merge may already have consumed part of them).
            const auto itT = out.terms.find(term);
            const auto itA = out.terms.find(term2);
            if (itT == out.terms.end() || itT->second != coeff) break;
            if (itA == out.terms.end() || itA->second != coeff2) break;
            const uint32_t sum = binary(Add, width, tn.a, tn.b);
            const int64_t merged =
                static_cast<int64_t>(out.terms[sum]) + coeff;
            if (merged) out.terms[sum] = merged;
            else out.terms.erase(sum);
            out.terms.erase(itT);
            out.terms.erase(itA);
            break;
        }
    }

    // Build the canonical sum, terms sorted by id.  A zero constant is
    // dropped when real terms exist (id 0 is reserved, so 0 = "unset").
    uint32_t result = 0;
    if (out.constant != 0 || out.terms.empty())
        result = constant(width, out.constant);
    for (const auto& [term, coeff] : out.terms) {
        uint32_t piece;
        if (coeff == 1) piece = term;
        else if (coeff == -1) piece = unary(Neg, width, term);
        else piece = binary(Mul, width, constant(width, coeff), term);
        if (!result) {
            result = piece;
        } else {
            result = binary(Add, width, result, piece);
        }
    }
    return result;
}

uint32_t Semantics::canon(uint32_t id, int depth) {
    if (depth > 32) return id;
    Node n = nodes_[id];
    switch (n.kind) {
    case Const:
        return constant(n.width, n.constant);
    case Var:
        return id;
    case Add:
    case Sub:
    case Neg: {
        // Canon children first so opaque term keys (nonlinear subterms) are
        // themselves canonical, then flatten the whole into the linear form.
        n.a = canon(n.a, depth + 1);
        if (n.b) n.b = canon(n.b, depth + 1);
        Linear lin;
        asLinear(mk(n), n.width, lin, 0);
        return fromLinear(lin, n.width);
    }
    case Mul: {
        // Distribute constant scalars over sums.
        n.a = canon(n.a, depth + 1);
        n.b = canon(n.b, depth + 1);
        Linear lin;
        asLinear(mk(n), n.width, lin, 0);
        return fromLinear(lin, n.width);
    }
    case Shl: {
        n.a = canon(n.a, depth + 1);
        n.b = canon(n.b, depth + 1);
        Linear lin;
        asLinear(mk(n), n.width, lin, 0);
        return fromLinear(lin, n.width);
    }
    case Slice:
    case ZExt: {
        n.a = canon(n.a, depth + 1);
        Linear lin;
        asLinear(mk(n), n.width, lin, 0);
        return fromLinear(lin, n.width);
    }
    case And:
    case Or:
    case Xor: {
        n.a = canon(n.a, depth + 1);
        n.b = canon(n.b, depth + 1);
        const Node& lhs = nodes_[n.a];
        const Node& rhs = nodes_[n.b];
        const uint64_t ones = mask(n.width);
        // Identities on constants.
        if (lhs.kind == Const && rhs.kind == Const) {
            uint64_t v = 0;
            switch (n.kind) {
            case And: v = lhs.constant & rhs.constant; break;
            case Or:  v = lhs.constant | rhs.constant; break;
            default:  v = lhs.constant ^ rhs.constant; break;
            }
            return constant(n.width, v);
        }
        if (lhs.kind == Const) {
            if (lhs.constant == 0)
                return n.kind == And ? constant(n.width, 0) : n.b;
            if (lhs.constant == ones)
                return n.kind == And ? n.b : constant(n.width, ones);
        }
        if (rhs.kind == Const) {
            if (rhs.constant == 0)
                return n.kind == And ? constant(n.width, 0) : n.a;
            if (rhs.constant == ones)
                return n.kind == And ? n.a : constant(n.width, ones);
        }
        if (n.a == n.b) {
            if (n.kind == Xor) return constant(n.width, 0);
            return n.a;  // And/Or idempotent
        }
        return mk(n);
    }
    case Not: {
        n.a = canon(n.a, depth + 1);
        if (nodes_[n.a].kind == Not) return nodes_[n.a].a;
        return mk(n);
    }
    case Eq:
    case Ne:
    case Ult:
    case Slt:
    case Ule:
    case Sle: {
        n.a = canon(n.a, depth + 1);
        n.b = canon(n.b, depth + 1);
        const Node& lhs = nodes_[n.a];
        const Node& rhs = nodes_[n.b];
        if (lhs.kind == Const && rhs.kind == Const) {
            bool truth = false;
            switch (n.kind) {
            case Eq: truth = lhs.constant == rhs.constant; break;
            case Ne: truth = lhs.constant != rhs.constant; break;
            case Ult: truth = lhs.constant < rhs.constant; break;
            case Slt:
                truth = static_cast<int64_t>(lhs.constant) <
                        static_cast<int64_t>(rhs.constant);
                break;
            case Ule: truth = lhs.constant <= rhs.constant; break;
            case Sle:
                truth = static_cast<int64_t>(lhs.constant) <=
                        static_cast<int64_t>(rhs.constant);
                break;
            default: break;
            }
            return constant(1, truth ? 1 : 0);
        }
        if (n.a == n.b) {
            if (n.kind == Eq || n.kind == Ule || n.kind == Sle)
                return constant(1, 1);
            if (n.kind == Ne || n.kind == Ult || n.kind == Slt)
                return constant(1, 0);
        }
        return mk(n);
    }
    case Ite: {
        n.a = canon(n.a, depth + 1);
        n.b = canon(n.b, depth + 1);
        n.c = canon(n.c, depth + 1);
        if (nodes_[n.a].kind == Const)
            return nodes_[n.a].constant ? n.b : n.c;
        if (n.b == n.c) return n.b;
        return mk(n);
    }
    default:
        n.a = canon(n.a, depth + 1);
        n.b = canon(n.b, depth + 1);
        return mk(n);
    }
}

uint32_t Semantics::simplify(uint32_t root) {
    // Canon until a fixed point: one round may expose new structure (an MBA
    // template merge produces a scalar multiple of a sum, which the next
    // round distributes).
    uint32_t cur = root;
    for (int i = 0; i < 8; ++i) {
        const uint32_t next = canon(cur, 0);
        if (next == cur) break;
        cur = next;
    }
    return cur;
}

// ---------------------------------------------------------------------------
// ANF prover
// ---------------------------------------------------------------------------

bool Semantics::anfOpXor(Anf& a, const Anf& b, size_t budget) {
    std::vector<uint64_t> out;
    out.reserve(a.monos.size() + b.monos.size());
    size_t i = 0, j = 0;
    while (i < a.monos.size() || j < b.monos.size()) {
        if (j >= b.monos.size() ||
            (i < a.monos.size() && a.monos[i] < b.monos[j]))
            out.push_back(a.monos[i++]);
        else if (i >= a.monos.size() || b.monos[j] < a.monos[i])
            out.push_back(b.monos[j++]);
        else {
            ++i;
            ++j;  // cancel
        }
    }
    if (out.size() > budget) return false;
    a.monos = std::move(out);
    return true;
}

bool Semantics::anfOpAnd(Anf& a, const Anf& b, size_t budget) {
    // GF(2) polynomial product.  Collect every pairwise monomial union,
    // sort, and cancel even multiplicities (adjacent duplicates toggle).
    // A hard pair cap keeps the bailout itself cheap: a result anywhere near
    // the budget would be unusable by the carry chains anyway.
    const size_t pairs = a.monos.size() * b.monos.size();
    if (pairs > budget * 4) return false;
    std::vector<uint64_t> prods;
    prods.reserve(pairs);
    for (const uint64_t ma : a.monos)
        for (const uint64_t mb : b.monos) prods.push_back(ma | mb);
    std::sort(prods.begin(), prods.end());
    std::vector<uint64_t> out;
    out.reserve(prods.size());
    for (size_t i = 0; i < prods.size();) {
        size_t j = i + 1;
        while (j < prods.size() && prods[j] == prods[i]) ++j;
        if ((j - i) & 1) out.push_back(prods[i]);
        i = j;
    }
    if (out.size() > budget) return false;
    a.monos = std::move(out);
    return true;
}

bool Semantics::anfOpOr(Anf& a, const Anf& b, size_t budget) {
    // a | b = a ^ b ^ (a & b)
    Anf ab = a;
    if (!anfOpAnd(ab, b, budget)) return false;
    if (!anfOpXor(ab, b, budget)) return false;
    if (!anfOpXor(ab, a, budget)) return false;
    a = std::move(ab);
    return true;
}

bool Semantics::blastBits(const Semantics& sem, uint32_t id, int lo, int hi,
                          const std::map<uint32_t, uint32_t>& atomBase,
                          std::map<uint64_t, Anf>& memo, size_t budget,
                          std::vector<Anf>& bits) {
    bits.clear();
    for (int b = lo; b < hi; ++b) {
        Anf a;
        if (!blast(sem, id, b, atomBase, memo, budget, a)) return false;
        bits.push_back(std::move(a));
    }
    return true;
}

bool Semantics::blast(const Semantics& sem, uint32_t id, int bit,
           const std::map<uint32_t, uint32_t>& atomBase,
           std::map<uint64_t, Semantics::Anf>& memo, size_t budget,
           Semantics::Anf& out) {
    const Semantics::Node& n = sem.node(id);
    const int w = n.width * 8;
    if (bit < 0 || bit >= w) {
        std::fprintf(stderr, "BAILW kind=%d width=%d bit=%d;", (int)n.kind,
                     (int)n.width, bit);
        return false;
    }
    const uint64_t key = (static_cast<uint64_t>(id) << 8) |
                         static_cast<uint64_t>(bit & 0xff);
    const auto cached = memo.find(key);
    if (cached != memo.end()) {
        out = cached->second;
        return true;
    }
    auto store = [&](const Semantics::Anf& a) {
        out = a;
        memo.emplace(key, a);
        return true;
    };
    Semantics::Anf zero;  // empty monomial list
    Semantics::Anf one{{0}};  // constant-1 monomial: empty atom mask

    switch (n.kind) {
    case Semantics::Const:
        return store((n.constant >> bit) & 1 ? one : zero);
    case Semantics::Var: {
        const auto base = atomBase.find(id);
        if (base == atomBase.end()) return false;
        const uint32_t atom = base->second + static_cast<uint32_t>(bit);
        if (atom >= 64) return false;
        Semantics::Anf a;
        a.monos.push_back(1ULL << atom);
        return store(a);
    }
    case Semantics::Not: {
        Semantics::Anf a;
        if (!blast(sem, n.a, bit, atomBase, memo, budget, a)) return false;
        if (!Semantics::anfOpXor(a, one, budget)) return false;
        return store(a);
    }
    case Semantics::Xor: {
        Semantics::Anf a, b;
        if (!blast(sem, n.a, bit, atomBase, memo, budget, a)) return false;
        if (!blast(sem, n.b, bit, atomBase, memo, budget, b)) return false;
        if (!Semantics::anfOpXor(a, b, budget)) return false;
        return store(a);
    }
    case Semantics::And: {
        // Constant short-circuit: (x & 0) bit is 0 without blasting x, and
        // (x & ~0) bit is x's bit.  Keeps high bits of masked values cheap.
        const Semantics::Node& ln = sem.node(n.a);
        const Semantics::Node& rn = sem.node(n.b);
        if (rn.kind == Semantics::Const) {
            if (!((rn.constant >> bit) & 1)) return store(zero);
            return blast(sem, n.a, bit, atomBase, memo, budget, out);
        }
        if (ln.kind == Semantics::Const) {
            if (!((ln.constant >> bit) & 1)) return store(zero);
            return blast(sem, n.b, bit, atomBase, memo, budget, out);
        }
        Semantics::Anf a, b;
        if (!blast(sem, n.a, bit, atomBase, memo, budget, a)) return false;
        if (!blast(sem, n.b, bit, atomBase, memo, budget, b)) return false;
        if (!Semantics::anfOpAnd(a, b, budget)) return false;
        return store(a);
    }
    case Semantics::Or: {
        const Semantics::Node& ln = sem.node(n.a);
        const Semantics::Node& rn = sem.node(n.b);
        if (rn.kind == Semantics::Const) {
            if ((rn.constant >> bit) & 1) return store(one);
            return blast(sem, n.a, bit, atomBase, memo, budget, out);
        }
        if (ln.kind == Semantics::Const) {
            if ((ln.constant >> bit) & 1) return store(one);
            return blast(sem, n.b, bit, atomBase, memo, budget, out);
        }
        Semantics::Anf a, b;
        if (!blast(sem, n.a, bit, atomBase, memo, budget, a)) return false;
        if (!blast(sem, n.b, bit, atomBase, memo, budget, b)) return false;
        if (!Semantics::anfOpOr(a, b, budget)) return false;
        return store(a);
    }
    case Semantics::Shl:
    case Semantics::Shr:
    case Semantics::Sar: {
        const Semantics::Node& rhs = sem.node(n.b);
        if (rhs.kind != Semantics::Const) return false;
        const int k = static_cast<int>(rhs.constant);
        if (n.kind == Semantics::Shl) {
            if (bit < k) return store(zero);
            return blast(sem, n.a, bit - k, atomBase, memo, budget, out);
        }
        if (bit + k >= w) {
            if (n.kind == Semantics::Sar)
                return blast(sem, n.a, w - 1, atomBase, memo, budget, out);
            return store(zero);
        }
        return blast(sem, n.a, bit + k, atomBase, memo, budget, out);
    }
    case Semantics::Slice: {
        const int srcBit = static_cast<int>(n.aux) * 8 + bit;
        return blast(sem, n.a, srcBit, atomBase, memo, budget, out);
    }
    case Semantics::ZExt:
        if (bit >= sem.node(n.a).width * 8) return store(zero);
        return blast(sem, n.a, bit, atomBase, memo, budget, out);
    case Semantics::SExt: {
        const int srcW = sem.node(n.a).width * 8;
        if (bit < srcW) return blast(sem, n.a, bit, atomBase, memo, budget, out);
        return blast(sem, n.a, srcW - 1, atomBase, memo, budget, out);
    }
    case Semantics::Neg: {
        // -a == ~a + 1; only bits 0..bit are needed.
        std::vector<Semantics::Anf> bits;
        if (!blastBits(sem, n.a, 0, bit + 1, atomBase, memo, budget, bits))
            return false;
        Semantics::Anf carry = one;
        Semantics::Anf result;
        for (int i = 0; i <= bit; ++i) {
            Semantics::Anf notA = bits[i];
            if (!Semantics::anfOpXor(notA, one, budget)) return false;
            Semantics::Anf sum = notA;
            if (!Semantics::anfOpXor(sum, carry, budget)) return false;
            if (i == bit) result = sum;
            if (i + 1 < w) {
                // carry' = maj(a, ~a, carry) simplifies to (notA & carry)
                Semantics::Anf c = notA;
                if (!Semantics::anfOpAnd(c, carry, budget)) return false;
                carry = std::move(c);
            }
        }
        return store(result);
    }
    case Semantics::Add:
    case Semantics::Sub: {
        // Only bits 0..bit are needed: carries propagate upward only.
        std::vector<Semantics::Anf> lhs, rhs;
        if (!blastBits(sem, n.a, 0, bit + 1, atomBase, memo, budget, lhs))
            return false;
        uint32_t bId = n.b;
        if (n.kind == Semantics::Sub) {
            // a - b == a + (~b) + 1
            Semantics::Anf carryIn = one;
            Semantics::Anf result;
            if (!blastBits(sem, bId, 0, bit + 1, atomBase, memo, budget, rhs))
                return false;
            Semantics::Anf carry = carryIn;
            for (int i = 0; i <= bit; ++i) {
                Semantics::Anf nb = rhs[i];
                if (!Semantics::anfOpXor(nb, one, budget)) return false;
                Semantics::Anf sum = lhs[i];
                if (!Semantics::anfOpXor(sum, nb, budget)) return false;
                if (!Semantics::anfOpXor(sum, carry, budget)) return false;
                if (i == bit) result = sum;
                if (i < bit) {
                    Semantics::Anf x = lhs[i];
                    if (!Semantics::anfOpXor(x, nb, budget)) return false;
                    Semantics::Anf c1 = x;
                    if (!Semantics::anfOpAnd(c1, carry, budget)) return false;
                    Semantics::Anf c2 = lhs[i];
                    if (!Semantics::anfOpAnd(c2, nb, budget)) return false;
                    if (!Semantics::anfOpXor(c1, c2, budget)) return false;
                    carry = std::move(c1);
                }
            }
            return store(result);
        }
        if (!blastBits(sem, bId, 0, bit + 1, atomBase, memo, budget, rhs))
            return false;
        Semantics::Anf carry;  // empty = 0
        Semantics::Anf result;
        for (int i = 0; i <= bit; ++i) {
            Semantics::Anf sum = lhs[i];
            if (!Semantics::anfOpXor(sum, rhs[i], budget)) return false;
            if (!Semantics::anfOpXor(sum, carry, budget)) return false;
            if (i == bit) result = sum;
            if (i < bit) {
                Semantics::Anf x = lhs[i];
                if (!Semantics::anfOpXor(x, rhs[i], budget)) return false;
                Semantics::Anf c1 = x;
                if (!Semantics::anfOpAnd(c1, carry, budget)) return false;
                Semantics::Anf c2 = lhs[i];
                if (!Semantics::anfOpAnd(c2, rhs[i], budget)) return false;
                if (!Semantics::anfOpXor(c1, c2, budget)) return false;
                carry = std::move(c1);
            }
        }
        return store(result);
    }
    case Semantics::Mul: {
        // Carry-save multiplier: supports fully symbolic operands.  Bit k of
        // the product is the GF(2) sum of every partial product a_i & b_j
        // with i + j == k, plus carries; a full adder reduces each position
        // to a sum bit and a carry into position k+1.  Only positions up to
        // the requested bit are computed.
        std::vector<Semantics::Anf> lhs, rhs;
        if (!blastBits(sem, n.a, 0, bit + 1, atomBase, memo, budget, lhs))
            return false;
        if (!blastBits(sem, n.b, 0, bit + 1, atomBase, memo, budget, rhs))
            return false;
        std::vector<std::vector<Semantics::Anf>> pos(bit + 1);
        for (int i = 0; i <= bit; ++i)
            for (int j = 0; j + i <= bit; ++j) {
                Semantics::Anf t = lhs[i];
                if (!Semantics::anfOpAnd(t, rhs[j], budget)) return false;
                if (!t.monos.empty()) pos[i + j].push_back(std::move(t));
            }
        std::vector<Semantics::Anf> incoming;  // carry bits into position k
        Semantics::Anf result;
        for (int k = 0; k <= bit; ++k) {
            std::vector<Semantics::Anf> bits;
            bits.reserve(pos[k].size() + incoming.size());
            for (auto& t : pos[k]) bits.push_back(std::move(t));
            for (auto& t : incoming) bits.push_back(std::move(t));
            incoming.clear();
            // Carry-save reduce to at most two bits at this position.
            while (bits.size() > 2) {
                Semantics::Anf x = std::move(bits.back());
                bits.pop_back();
                Semantics::Anf y = std::move(bits.back());
                bits.pop_back();
                Semantics::Anf z = std::move(bits.back());
                bits.pop_back();
                Semantics::Anf s = x;
                if (!Semantics::anfOpXor(s, y, budget)) return false;
                if (!Semantics::anfOpXor(s, z, budget)) return false;
                bits.push_back(std::move(s));
                Semantics::Anf xy = x;
                if (!Semantics::anfOpAnd(xy, y, budget)) return false;
                Semantics::Anf xz = x;
                if (!Semantics::anfOpAnd(xz, z, budget)) return false;
                Semantics::Anf yz = y;
                if (!Semantics::anfOpAnd(yz, z, budget)) return false;
                Semantics::Anf c = std::move(xy);
                if (!Semantics::anfOpXor(c, xz, budget)) return false;
                if (!Semantics::anfOpXor(c, yz, budget)) return false;
                if (!c.monos.empty()) incoming.push_back(std::move(c));
            }
            if (k == bit) {
                // Sum bit: XOR of everything left (possibly nothing = 0).
                if (!bits.empty()) {
                    result = std::move(bits.back());
                    bits.pop_back();
                    while (!bits.empty()) {
                        if (!Semantics::anfOpXor(result, bits.back(), budget))
                            return false;
                        bits.pop_back();
                    }
                }
            } else {
                // Two remaining bits: one stays, one carries into k+1.
                if (bits.size() == 2) {
                    Semantics::Anf c = bits[0];
                    if (!Semantics::anfOpAnd(c, bits[1], budget)) return false;
                    if (!c.monos.empty())
                        incoming.push_back(std::move(c));
                }
            }
        }
        return store(result);
    }
    case Semantics::Ite: {
        Semantics::Anf c, t, e;
        if (!blast(sem, n.a, 0, atomBase, memo, budget, c)) return false;
        if (!blast(sem, n.b, bit, atomBase, memo, budget, t)) return false;
        if (!blast(sem, n.c, bit, atomBase, memo, budget, e)) return false;
        // b ^ (c & (t ^ e))
        Semantics::Anf te = t;
        if (!Semantics::anfOpXor(te, e, budget)) return false;
        if (!Semantics::anfOpAnd(c, te, budget)) return false;
        if (!Semantics::anfOpXor(e, c, budget)) return false;
        return store(e);
    }
    case Semantics::Eq:
    case Semantics::Ne: {
        if (bit != 0) return store(zero);
        const int aw = sem.node(n.a).width * 8;
        std::vector<Semantics::Anf> lhs, rhs;
        if (!blastBits(sem, n.a, 0, aw, atomBase, memo, budget, lhs))
            return false;
        if (!blastBits(sem, n.b, 0, aw, atomBase, memo, budget, rhs))
            return false;
        Semantics::Anf diff;
        for (int i = 0; i < aw; ++i) {
            Semantics::Anf d = lhs[i];
            if (!Semantics::anfOpXor(d, rhs[i], budget)) return false;
            if (!Semantics::anfOpOr(diff, d, budget)) return false;
        }
        if (n.kind == Semantics::Ne) return store(diff);
        if (!Semantics::anfOpXor(diff, one, budget)) return false;
        return store(diff);
    }
    case Semantics::Ule:
    case Semantics::Ult: {
        if (bit != 0) return store(zero);
        const int aw = sem.node(n.a).width * 8;
        std::vector<Semantics::Anf> lhs, rhs;
        if (!blastBits(sem, n.a, 0, aw, atomBase, memo, budget, lhs))
            return false;
        if (!blastBits(sem, n.b, 0, aw, atomBase, memo, budget, rhs))
            return false;
        // borrow-out of a - b, true when a < b:
        //   borrow' = maj(~a, b, borrow) = ~(a^b)&borrow ^ ~a&b
        Semantics::Anf borrow;
        for (int i = 0; i < aw; ++i) {
            Semantics::Anf na = lhs[i];
            if (!Semantics::anfOpXor(na, one, budget)) return false;  // ~a
            Semantics::Anf x = na;
            if (!Semantics::anfOpXor(x, rhs[i], budget)) return false;  // ~(a^b)
            Semantics::Anf c1 = x;
            if (!Semantics::anfOpAnd(c1, borrow, budget)) return false;
            Semantics::Anf c2 = na;
            if (!Semantics::anfOpAnd(c2, rhs[i], budget)) return false;  // ~a & b
            if (!Semantics::anfOpXor(c1, c2, budget)) return false;
            borrow = std::move(c1);
        }
        if (n.kind == Semantics::Ult) return store(borrow);
        if (!Semantics::anfOpXor(borrow, one, budget)) return false;
        return store(borrow);
    }
    default:
        return false;  // unsupported: bail -> Unknown
    }
}

// Assign atom bases to every Var leaf reachable from root, sorted by id for
// determinism.  Returns false when more than 64 atoms are required.
static bool collectAtoms(const Semantics& sem, uint32_t id,
                  std::vector<uint32_t>& outIds) {
    outIds.clear();
    std::vector<uint32_t> stack{id};
    std::map<uint32_t, bool> visited;
    while (!stack.empty()) {
        const uint32_t cur = stack.back();
        stack.pop_back();
        if (!visited.insert({cur, true}).second) continue;
        const Semantics::Node& n = sem.node(cur);
        if (n.kind == Semantics::Var) {
            outIds.push_back(cur);
            continue;
        }
        if (n.a) stack.push_back(n.a);
        if (n.b) stack.push_back(n.b);
        if (n.c) stack.push_back(n.c);
    }
    std::sort(outIds.begin(), outIds.end());
    outIds.erase(std::unique(outIds.begin(), outIds.end()), outIds.end());
    size_t atoms = 0;
    for (const uint32_t varId : outIds)
        atoms += sem.node(varId).width * 8;
    return atoms <= 64;
}

Semantics::Truth Semantics::proveCondition(uint32_t cond) {
    if (nodes_[cond].width != 1) return Truth::Unknown;
    std::vector<uint32_t> vars;
    if (!collectAtoms(*this, cond, vars)) return Truth::Unknown;
    std::map<uint32_t, uint32_t> atomBase;
    uint32_t base = 0;
    for (const uint32_t varId : vars) {
        atomBase.emplace(varId, base);
        base += nodes_[varId].width * 8;
    }
    std::map<uint64_t, Anf> memo;
    Anf result;
    if (!blast(*this, cond, 0, atomBase, memo, anfMonomialBudget, result))
        return Truth::Unknown;
    if (result.monos.empty()) return Truth::AlwaysFalse;
    if (result.monos.size() == 1 && result.monos[0] == 0)
        return Truth::AlwaysTrue;
    return Truth::Unknown;
}

std::optional<uint64_t> Semantics::proveConstant(uint32_t a) {
    // Canonical simplification resolves constant expressions (folding,
    // like-term merge, MBA templates) without any bit-blasting.
    const uint32_t s = simplify(a);
    if (nodes_[s].kind == Const) return nodes_[s].constant;
    a = s;
    std::vector<uint32_t> vars;
    if (!collectAtoms(*this, a, vars)) return std::nullopt;
    std::map<uint32_t, uint32_t> atomBase;
    uint32_t base = 0;
    for (const uint32_t varId : vars) {
        atomBase.emplace(varId, base);
        base += nodes_[varId].width * 8;
    }
    std::map<uint64_t, Anf> memo;
    const int w = nodes_[a].width * 8;
    uint64_t value = 0;
    for (int bit = 0; bit < w; ++bit) {
        Anf r;
        if (!blast(*this, a, bit, atomBase, memo, anfMonomialBudget, r))
            return std::nullopt;
        if (r.monos.empty()) continue;
        if (r.monos.size() == 1 && r.monos[0] == 0) {
            value |= 1ULL << bit;
            continue;
        }
        return std::nullopt;
    }
    return value;
}

bool Semantics::proveEqual(uint32_t a, uint32_t b) {
    if (nodes_[a].width != nodes_[b].width) return false;
    // Cheap canonical-form equality first: the linear-algebra normal form
    // collapses MBA templates without any bit-blasting.
    if (simplify(a) == simplify(b)) return true;
    // Residual proofs (e.g. boolean identities the rewriter misses) go
    // through the ANF bit-blaster; carry-chain blow-up is budget-capped and
    // answers "unknown" (= false here, never a wrong proof).
    const uint32_t diff = binary(Xor, nodes_[a].width, a, b);
    const auto value = proveConstant(diff);
    return value.has_value() && *value == 0;
}

// ---------------------------------------------------------------------------
// C emission
// ---------------------------------------------------------------------------

namespace {

const char* binOpName(Semantics::Kind k) {
    switch (k) {
    case Semantics::Add: return "+";
    case Semantics::Sub: return "-";
    case Semantics::Mul: return "*";
    case Semantics::UDiv: return "/";
    case Semantics::URem: return "%";
    case Semantics::SRem: return "%";
    case Semantics::And: return "&";
    case Semantics::Or: return "|";
    case Semantics::Xor: return "^";
    case Semantics::Shl: return "<<";
    case Semantics::Shr: return ">>";
    case Semantics::Sar: return ">>";
    case Semantics::Eq: return "==";
    case Semantics::Ne: return "!=";
    case Semantics::Ult: return "<";
    case Semantics::Slt: return "<";
    case Semantics::Ule: return "<=";
    case Semantics::Sle: return "<=";
    default: return "?";
    }
}

int precedence(Semantics::Kind k) {
    switch (k) {
    case Semantics::Or: return 1;
    case Semantics::Xor: return 2;
    case Semantics::And: return 3;
    case Semantics::Eq: case Semantics::Ne:
    case Semantics::Ult: case Semantics::Slt:
    case Semantics::Ule: case Semantics::Sle: return 4;
    case Semantics::Shl: case Semantics::Shr: case Semantics::Sar: return 5;
    case Semantics::Add: case Semantics::Sub: return 6;
    case Semantics::Mul: case Semantics::UDiv: case Semantics::URem:
    case Semantics::SRem: return 7;
    default: return 8;
    }
}

void emit(const Semantics& sem, uint32_t id, int parentPrec,
          const std::map<uint64_t, std::string>& names, std::string& out) {
    const Semantics::Node& n = sem.node(id);
    auto paren = [&](const std::string& s, int prec) {
        if (prec < parentPrec) {
            out += "(";
            out += s;
            out += ")";
        } else {
            out += s;
        }
    };
    std::string s;
    const int myPrec = precedence(n.kind);
    switch (n.kind) {
    case Semantics::Const: {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(n.constant));
        s = buf;
        break;
    }
    case Semantics::Var: {
        const auto found = names.find(n.varId);
        if (found != names.end()) {
            s = found->second;
        } else {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "v%llu",
                          static_cast<unsigned long long>(n.varId));
            s = buf;
        }
        break;
    }
    case Semantics::Not: {
        std::string inner;
        emit(sem, n.a, 8, names, inner);
        s = "~" + inner;
        break;
    }
    case Semantics::Neg: {
        std::string inner;
        emit(sem, n.a, 8, names, inner);
        s = "-" + inner;
        break;
    }
    case Semantics::ZExt:
    case Semantics::SExt: {
        emit(sem, n.a, 8, names, s);
        break;
    }
    case Semantics::Slice: {
        emit(sem, n.a, 8, names, s);
        break;
    }
    case Semantics::Ite: {
        std::string c, t, e;
        emit(sem, n.a, 8, names, c);
        emit(sem, n.b, 8, names, t);
        emit(sem, n.c, 8, names, e);
        s = c + " ? " + t + " : " + e;
        break;
    }
    default: {
        std::string lhs, rhs;
        emit(sem, n.a, myPrec, names, lhs);
        emit(sem, n.b, myPrec + (n.kind == Semantics::Sub ? 1 : 0), names,
             rhs);
        s = lhs + " " + binOpName(n.kind) + " " + rhs;
        break;
    }
    }
    paren(s, myPrec);
}

}  // namespace

std::string Semantics::toC(uint32_t root,
                           const std::map<uint64_t, std::string>& names) const {
    std::string out;
    emit(*this, root, 0, names, out);
    return out;
}

}  // namespace centrifuge
