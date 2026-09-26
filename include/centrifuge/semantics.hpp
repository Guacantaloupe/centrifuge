// Semantic equivalence engine for deobfuscation.
//
// The pipeline this feeds: 混淆机器码 -> P-code/SSA -> SymExpr -> 化简/证明
// -> 删除表示层噪声 -> 重建 CFG/SSA -> fixed point.
//
// Two cooperating layers:
//
//  * Canonical simplifier (rewrite + linear-algebra normal form): produces
//    the human-readable small expression emitted back into decompiled C.
//    Handles constant folding, like-term merging, distribution, the
//    x+y == (x^y) + 2*(x&y) MBA template family, and width truncation.
//
//  * Bit-blasting ANF prover: translates any word expression over
//    {+,-,*,&,|,^,~,shifts,comparisons,select} into per-output-bit algebraic
//    normal form over input bits.  ANF is a canonical form, so structural
//    equality of ANFs IS a proof of semantic equivalence mod 2^(8*width).
//    Drives opaque-predicate elimination and verifies rewrite rules.
//    Budget-capped: on blow-up the proof answers "unknown", never wrong.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace centrifuge {

class Semantics {
public:
    Semantics();

    enum Kind : uint16_t {
        Const, Var,
        Add, Sub, Mul, UDiv, SRem, URem,
        And, Or, Xor, Not, Neg,
        Shl, Shr, Sar,
        Slice,   // aux = byte offset into the (wider) operand
        ZExt, SExt,
        Eq, Ne, Ult, Slt, Ule, Sle,
        Ite,
    };
    struct Node {
        Kind kind = Const;
        uint8_t width = 8;      // result width in bytes (1..8)
        uint64_t constant = 0;  // Const value, masked to width
        uint64_t varId = 0;     // Var: stable input identifier
        uint32_t a = 0, b = 0, c = 0;  // child node ids (0 = none)
        uint64_t aux = 0;       // Slice byte offset / unused
    };

    // ---- construction (all nodes interned: equal subtrees share an id) ----
    uint32_t constant(uint8_t width, uint64_t value);
    uint32_t variable(uint8_t width, uint64_t varId);
    uint32_t unary(Kind kind, uint8_t width, uint32_t a);
    uint32_t binary(Kind kind, uint8_t width, uint32_t a, uint32_t b);
    uint32_t slice(uint8_t width, uint32_t a, uint64_t byteOffset);
    uint32_t ite(uint8_t width, uint32_t cond, uint32_t then_, uint32_t else_);

    const Node& node(uint32_t id) const { return nodes_.at(id); }
    uint8_t width(uint32_t id) const { return nodes_.at(id).width; }
    uint64_t mask(uint8_t width) const;

    // ---- canonical simplification (readability layer) ----
    // Returns the canonical node id.  Linear sub-expressions are normalized
    // into sorted, coefficient-merged sums; boolean identities are folded;
    // the x+y == (x^y)+2*(x&y) template family collapses back to arithmetic.
    uint32_t simplify(uint32_t root);

    // ---- equivalence proofs (bit-blast + ANF layer) ----
    enum class Truth { AlwaysTrue, AlwaysFalse, Unknown };
    Truth proveCondition(uint32_t cond);            // width must be 1
    bool proveEqual(uint32_t a, uint32_t b);        // same width required
    // If the expression is constant, return its value (else nullopt).
    std::optional<uint64_t> proveConstant(uint32_t a);

    // ---- emission ----
    std::string toC(uint32_t root,
                    const std::map<uint64_t, std::string>& varNames = {}) const;

    // Proof budget: max ANF monomials per bit before giving up.
    size_t anfMonomialBudget = 4096;

private:
    struct NodeKeyLess {
        bool operator()(const Node& x, const Node& y) const;
    };
    std::vector<Node> nodes_;                 // arena; index 0 reserved
    std::map<Node, uint32_t, NodeKeyLess> intern_;
    uint32_t mk(Node node);

    // Canonical linear form: coefficients keyed by canonical sub-term id.
    struct Linear {
        std::map<uint32_t, int64_t> terms;  // term id -> coefficient
        uint64_t constant = 0;              // already masked to width
    };
    bool asLinear(uint32_t id, uint8_t width, Linear& out, int depth);
    uint32_t fromLinear(const Linear& lin, uint8_t width);
    uint32_t canon(uint32_t id, int depth);

    // ANF over boolean atoms; each monomial is a 64-bit atom mask, so at
    // most 64 atoms (= e.g. eight 64-bit or sixty-four 1-bit leaf vars) can
    // participate in a single proof.  More leaves -> Unknown.
    struct Anf {
        std::vector<uint64_t> monos;  // sorted, deduped
    };
    static bool anfOpOr(Anf& a, const Anf& b, size_t budget);
    static bool anfOpXor(Anf& a, const Anf& b, size_t budget);
    static bool anfOpAnd(Anf& a, const Anf& b, size_t budget);

    // Bit-blasting proof kernel: translate one output bit of `id` into ANF
    // over the boolean atoms assigned by atomBase (bit offset per Var leaf).
    static bool blast(const Semantics& sem, uint32_t id, int bit,
                      const std::map<uint32_t, uint32_t>& atomBase,
                      std::map<uint64_t, Anf>& memo, size_t budget, Anf& out);
    static bool blastBits(const Semantics& sem, uint32_t id, int lo, int hi,
                          const std::map<uint32_t, uint32_t>& atomBase,
                          std::map<uint64_t, Anf>& memo, size_t budget,
                          std::vector<Anf>& bits);
};

}  // namespace centrifuge
