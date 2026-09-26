// Semantics engine unit tests: canonical simplifier, MBA template collapse,
// opaque-predicate proofs, and ANF-based equivalence proving.
#include <cstdio>
#include <cstdio>
#include <map>
#include <string>

#include "centrifuge/semantics.hpp"

using namespace centrifuge;

namespace {
int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++failures; } } while (0)

// Build (x ^ y) + 2 * (x & y), the canonical 32-bit MBA obfuscation of x + y.
uint32_t mbaXY(Semantics& sem, uint32_t x, uint32_t y) {
    const uint32_t xw = sem.binary(Semantics::Xor, 4, x, y);
    const uint32_t aw = sem.binary(Semantics::And, 4, x, y);
    const uint32_t two = sem.constant(4, 2);
    const uint32_t twice = sem.binary(Semantics::Mul, 4, two, aw);
    return sem.binary(Semantics::Add, 4, xw, twice);
}

void testSimplifyBasics() {
    Semantics sem;
    const uint32_t x = sem.variable(4, 1);
    const uint32_t y = sem.variable(4, 2);

    // x + x  ->  2 * x  (like-term merge through the linear form).
    const uint32_t xx = sem.binary(Semantics::Add, 4, x, x);
    const uint32_t sx = sem.simplify(xx);
    CHECK(sem.node(sx).kind == Semantics::Mul, "x+x simplifies to 2*x");
    CHECK(sem.node(sx).a == sem.constant(4, 2) ||
              sem.node(sx).b == sem.constant(4, 2),
          "x+x has constant factor 2");

    // (x + 5) - 5  ->  x  (constant folding).
    const uint32_t k5 = sem.constant(4, 5);
    const uint32_t folded =
        sem.binary(Semantics::Sub, 4,
                   sem.binary(Semantics::Add, 4, x, k5), k5);
    CHECK(sem.simplify(folded) == x, "(x+5)-5 folds to x");

    // x ^ 0  ->  x.
    const uint32_t xored =
        sem.binary(Semantics::Xor, 4, x, sem.constant(4, 0));
    CHECK(sem.simplify(xored) == x, "x^0 folds to x");

    // x & x  ->  x.
    const uint32_t anded = sem.binary(Semantics::And, 4, x, x);
    CHECK(sem.simplify(anded) == x, "x&x folds to x");

    // ~~x  ->  x.
    const uint32_t notted =
        sem.unary(Semantics::Not, 4,
                  sem.unary(Semantics::Not, 4, x));
    CHECK(sem.simplify(notted) == x, "double Not folds to x");

    // x + y  stays x + y (already canonical).
    const uint32_t sum = sem.binary(Semantics::Add, 4, x, y);
    CHECK(sem.simplify(sum) == sum, "x+y is already canonical");
}

void testMbaTemplate() {
    Semantics sem;
    const uint32_t x = sem.variable(4, 1);
    const uint32_t y = sem.variable(4, 2);
    const uint32_t mba = mbaXY(sem, x, y);
    const uint32_t sum = sem.binary(Semantics::Add, 4, x, y);

    // Simplify must collapse the MBA back to a plain add.
    const uint32_t collapsed = sem.simplify(mba);
    CHECK(collapsed == sum, "simplify collapses (x^y)+2*(x&y) to x+y");

    // The ANF prover must agree, both directions.
    CHECK(sem.proveEqual(mba, sum), "ANF proves MBA == x+y");
    CHECK(sem.proveEqual(sum, mba), "ANF proves x+y == MBA");

    // And it must NOT prove x+y equal to something else.
    const uint32_t wrong = sem.binary(Semantics::Sub, 4, x, y);
    CHECK(!sem.proveEqual(mba, wrong), "ANF rejects MBA == x-y");

    // Scaled variant: 3*(x^y) + 6*(x&y) == 3*(x+y).
    Semantics sem2;
    const uint32_t x2 = sem2.variable(4, 1);
    const uint32_t y2 = sem2.variable(4, 2);
    const uint32_t xw = sem2.binary(Semantics::Xor, 4, x2, y2);
    const uint32_t aw = sem2.binary(Semantics::And, 4, x2, y2);
    const uint32_t three = sem2.constant(4, 3);
    const uint32_t six = sem2.constant(4, 6);
    const uint32_t scaled = sem2.binary(
        Semantics::Add, 4,
        sem2.binary(Semantics::Mul, 4, three, xw),
        sem2.binary(Semantics::Mul, 4, six, aw));
    const uint32_t scaledSum =
        sem2.binary(Semantics::Mul, 4, three,
                    sem2.binary(Semantics::Add, 4, x2, y2));
    CHECK(sem2.proveEqual(scaled, scaledSum), "ANF proves scaled MBA");
}

void testOpaquePredicates() {
    Semantics sem;
    const uint32_t v = sem.variable(4, 1);

    // Classic opaque predicate: (v*v + v) is always even.
    // ANF must prove ((v*v + v) & 1) == 0 without any template knowledge.
    const uint32_t vv = sem.binary(Semantics::Mul, 4, v, v);
    const uint32_t expr = sem.binary(Semantics::Add, 4, vv, v);
    const uint32_t lowBit = sem.binary(Semantics::And, 4, expr,
                                       sem.constant(4, 1));
    const uint32_t cond = sem.binary(Semantics::Eq, 1, lowBit,
                                     sem.constant(4, 0));
    CHECK(sem.proveCondition(cond) == Semantics::Truth::AlwaysTrue,
          "(v*v+v)&1 == 0 is always true");

    // Always-false variant: (v & 1) == 2 can never hold.
    const uint32_t odd = sem.binary(Semantics::And, 4, v, sem.constant(4, 1));
    const uint32_t cond2 = sem.binary(Semantics::Eq, 1, odd,
                                      sem.constant(4, 2));
    CHECK(sem.proveCondition(cond2) == Semantics::Truth::AlwaysFalse,
          "(v&1) == 2 is always false");

    // A real condition must stay Unknown: v & 1 == 1 depends on v.
    const uint32_t cond3 = sem.binary(Semantics::Eq, 1, odd,
                                      sem.constant(4, 1));
    CHECK(sem.proveCondition(cond3) == Semantics::Truth::Unknown,
          "(v&1) == 1 stays unknown");

    // (v & 1) < 2 (unsigned, 8-bit) is always true; exercises the ANF
    // borrow chain without wrap-around (v < v+1 is NOT always true at any
    // width because of overflow, so it cannot be used here).
    Semantics sem8;
    const uint32_t v8 = sem8.variable(1, 1);
    const uint32_t cond4 = sem8.binary(
        Semantics::Ult, 1,
        sem8.binary(Semantics::And, 1, v8, sem8.constant(1, 1)),
        sem8.constant(1, 2));
    CHECK(sem8.proveCondition(cond4) == Semantics::Truth::AlwaysTrue,
          "(v&1) < 2 is always true");
}

void testProveConstant() {
    Semantics sem;
    const uint32_t x = sem.variable(4, 1);

    // (x ^ 0xff) ^ 0xff is not constant...
    const uint32_t masked = sem.binary(
        Semantics::Xor, 4,
        sem.binary(Semantics::Xor, 4, x, sem.constant(4, 0xff)),
        sem.constant(4, 0xff));
    CHECK(!sem.proveConstant(masked).has_value(),
          "(x^0xff)^0xff is not constant");
    // ...but it IS equal to x.
    CHECK(sem.proveEqual(masked, x), "(x^0xff)^0xff == x");

    // A genuinely constant expression: ((5 ^ 3) + 2 * (5 & 3)) == 8.
    Semantics sem2;
    const uint32_t five = sem2.constant(4, 5);
    const uint32_t three = sem2.constant(4, 3);
    const uint32_t expr = mbaXY(sem2, five, three);
    const auto val = sem2.proveConstant(expr);
    CHECK(val.has_value() && *val == 8, "MBA of constants proves to 8");
}

void testToC() {
    Semantics sem;
    const uint32_t x = sem.variable(4, 1);
    const uint32_t y = sem.variable(4, 2);
    const uint32_t mba = sem.simplify(mbaXY(sem, x, y));
    std::map<uint64_t, std::string> names{{1, "x"}, {2, "y"}};
    const std::string code = sem.toC(mba, names);
    CHECK(code == "x + y", "toC emits x + y for collapsed MBA");
}

void testWidthHandling() {
    // 16-bit MBA: two 16-bit vars = 32 atoms, well inside the 64-atom ANF
    // limit, while exercising a non-default word width.
    Semantics sem;
    const uint32_t x = sem.variable(2, 1);
    const uint32_t y = sem.variable(2, 2);
    const uint32_t xw = sem.binary(Semantics::Xor, 2, x, y);
    const uint32_t aw = sem.binary(Semantics::And, 2, x, y);
    const uint32_t mba = sem.binary(
        Semantics::Add, 2, xw,
        sem.binary(Semantics::Mul, 2, sem.constant(2, 2), aw));
    const uint32_t sum = sem.binary(Semantics::Add, 2, x, y);
    CHECK(sem.simplify(mba) == sum, "16-bit MBA collapses to x+y");
    CHECK(sem.proveEqual(mba, sum), "16-bit MBA proves equal");

    // 32-bit single-var opaque predicate: (v*v + v) & 1 == 0.  One 32-bit
    // leaf = 32 atoms; exercises the full-width multiply carry chain.
    Semantics sem32;
    const uint32_t v = sem32.variable(4, 1);
    const uint32_t expr = sem32.binary(
        Semantics::Add, 4, sem32.binary(Semantics::Mul, 4, v, v), v);
    const uint32_t cond = sem32.binary(
        Semantics::Eq, 1,
        sem32.binary(Semantics::And, 4, expr, sem32.constant(4, 1)),
        sem32.constant(4, 0));
    CHECK(sem32.proveCondition(cond) == Semantics::Truth::AlwaysTrue,
          "32-bit (v*v+v)&1 == 0 is always true");

    // Byte truncation: (uint8_t)(x + 256) == (uint8_t)x.
    Semantics semt;
    const uint32_t xt = semt.variable(1, 1);
    const uint32_t wide = semt.binary(Semantics::Add, 2, xt,
                                      semt.constant(2, 256));
    const uint32_t trunc = semt.slice(1, wide, 0);
    CHECK(semt.proveEqual(trunc, xt), "byte truncation of x+256 == x");
}

}  // namespace

int main() {
    testSimplifyBasics();
    testMbaTemplate();
    testOpaquePredicates();
    testProveConstant();
    testToC();
    testWidthHandling();
    if (failures) {
        std::printf("%d test(s) failed\n", failures);
        return 1;
    }
    std::printf("all semantics tests passed\n");
    return 0;
}
