// centrifuge - a Ghidra reimplementation in C++17
// pcode.cpp - p-code names + interpreter
#include "centrifuge/pcode.hpp"

#include <cmath>
#include <cstring>
#include <cstdio>
#include <limits>

namespace centrifuge {

const char* pOpName(POp p) {
    switch (p) {
    case POp::COPY: return "COPY";
    case POp::LOAD: return "LOAD";
    case POp::STORE: return "STORE";
    case POp::BRANCH: return "BRANCH";
    case POp::CBRANCH: return "CBRANCH";
    case POp::BRANCHIND: return "BRANCHIND";
    case POp::CALL: return "CALL";
    case POp::CALLIND: return "CALLIND";
    case POp::RETURN: return "RETURN";
    case POp::INT_EQUAL: return "INT_EQUAL";
    case POp::INT_NOTEQUAL: return "INT_NOTEQUAL";
    case POp::INT_LESS: return "INT_LESS";
    case POp::INT_SLESS: return "INT_SLESS";
    case POp::INT_LESSEQUAL: return "INT_LESSEQUAL";
    case POp::INT_SLESSEQUAL: return "INT_SLESSEQUAL";
    case POp::INT_ZEXT: return "INT_ZEXT";
    case POp::INT_SEXT: return "INT_SEXT";
    case POp::INT_ADD: return "INT_ADD";
    case POp::INT_SUB: return "INT_SUB";
    case POp::INT_NEGATE: return "INT_NEGATE";
    case POp::INT_XOR: return "INT_XOR";
    case POp::INT_AND: return "INT_AND";
    case POp::INT_OR: return "INT_OR";
    case POp::INT_LEFT: return "INT_LEFT";
    case POp::INT_RIGHT: return "INT_RIGHT";
    case POp::INT_SRIGHT: return "INT_SRIGHT";
    case POp::INT_MULT: return "INT_MULT";
    case POp::INT_DIV: return "INT_DIV";
    case POp::INT_SDIV: return "INT_SDIV";
    case POp::INT_REM: return "INT_REM";
    case POp::INT_SREM: return "INT_SREM";
    case POp::INT_CARRY: return "INT_CARRY";
    case POp::INT_SCARRY: return "INT_SCARRY";
    case POp::INT_SBORROW: return "INT_SBORROW";
    case POp::INT_PARITY: return "INT_PARITY";
    case POp::INT_POPCOUNT: return "INT_POPCOUNT";
    case POp::INT_COUNT_LEADING_ZERO: return "INT_COUNT_LEADING_ZERO";
    case POp::INT_COUNT_TRAILING_ZERO: return "INT_COUNT_TRAILING_ZERO";
    case POp::INT_MULT_OVERFLOW: return "INT_MULT_OVERFLOW";
    case POp::INT_SMULT_OVERFLOW: return "INT_SMULT_OVERFLOW";
    case POp::FLOAT_EQUAL: return "FLOAT_EQUAL";
    case POp::FLOAT_NOTEQUAL: return "FLOAT_NOTEQUAL";
    case POp::FLOAT_LESS: return "FLOAT_LESS";
    case POp::FLOAT_LESSEQUAL: return "FLOAT_LESSEQUAL";
    case POp::FLOAT_NAN: return "FLOAT_NAN";
    case POp::FLOAT_ADD: return "FLOAT_ADD";
    case POp::FLOAT_SUB: return "FLOAT_SUB";
    case POp::FLOAT_MULT: return "FLOAT_MULT";
    case POp::FLOAT_DIV: return "FLOAT_DIV";
    case POp::FLOAT_NEG: return "FLOAT_NEG";
    case POp::FLOAT_ABS: return "FLOAT_ABS";
    case POp::FLOAT_SQRT: return "FLOAT_SQRT";
    case POp::FLOAT_MIN: return "FLOAT_MIN";
    case POp::FLOAT_MAX: return "FLOAT_MAX";
    case POp::FLOAT_INT2FLOAT: return "FLOAT_INT2FLOAT";
    case POp::FLOAT_FLOAT2INT: return "FLOAT_FLOAT2INT";
    case POp::FLOAT_FLOAT2FLOAT: return "FLOAT_FLOAT2FLOAT";
    case POp::BOOL_NEGATE: return "BOOL_NEGATE";
    case POp::BOOL_XOR: return "BOOL_XOR";
    case POp::BOOL_AND: return "BOOL_AND";
    case POp::BOOL_OR: return "BOOL_OR";
    case POp::PIECE: return "PIECE";
    case POp::SUBPIECE: return "SUBPIECE";
    case POp::SELECT: return "SELECT";
    case POp::UNIMPLEMENTED: return "UNIMPLEMENTED";
    }
    return "?";
}

std::string PcodeInsn::varnodeName(uint64_t id) const {
    const Varnode* v = find(id);
    if (!v) return "<none>";
    if (v->kind == Varnode::CONST) {
        char buf[24];
        if (v->size <= 4)
            std::snprintf(buf, sizeof(buf), "0x%x",
                          static_cast<unsigned>(v->offset));
        else
            std::snprintf(buf, sizeof(buf), "0x%llx",
                          static_cast<unsigned long long>(v->offset));
        return buf;
    }
    if (!v->name.empty()) return v->name;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "u%llu",
                  static_cast<unsigned long long>(v->offset));
    return buf;
}

// ---- interpreter ----
namespace {

uint64_t sextVal(uint64_t v, int fromBits) {
    if (fromBits >= 64) return v;
    const uint64_t sign = 1ULL << (fromBits - 1);
    const uint64_t mask = (1ULL << fromBits) - 1;
    return ((v & mask) ^ sign) - sign;
}

uint64_t maskVal(uint64_t v, int bytes) {
    const int bits = bytes * 8;
    return bits > 0 && bits < 64 ? (v & ((1ULL << bits) - 1)) : v;
}

} // namespace

void PcodeEvaluator::run() {
    vals_.clear();
    wideVals_.clear();
    lastBranch_.reset();
    branchTaken_ = false;
    for (const auto& op : insn_.ops) {
        const Varnode* out = insn_.find(op.out);
        const Varnode* storeValue = insn_.find(op.in2);
        const bool wide = (out && out->size > 8) ||
                          (op.op == POp::STORE && storeValue && storeValue->size > 8);
        if (wide) {
            auto value = evalWideOp(op);
            if (op.out) {
                wideVals_[op.out] = value;
                if (value && !value->empty()) {
                    uint64_t low = 0;
                    std::memcpy(&low, value->data(), std::min<size_t>(8, value->size()));
                    vals_[op.out] = low;
                }
            }
            continue;
        }
        std::optional<uint64_t> r = evalOp(op);
        if (op.out != 0) vals_[op.out] = r;
    }
}

std::optional<std::vector<uint8_t>> PcodeEvaluator::wideValue(uint64_t id) const {
    const auto known = wideVals_.find(id);
    if (known != wideVals_.end()) return known->second;
    const Varnode* v = insn_.find(id);
    if (!v) return std::nullopt;
    const auto scalar = vals_.find(id);
    if (scalar != vals_.end() && scalar->second) {
        std::vector<uint8_t> value(static_cast<size_t>(v->size), 0);
        std::memcpy(value.data(), &*scalar->second,
                    std::min<size_t>(8, value.size()));
        return value;
    }
    if (v->kind == Varnode::REGISTER) {
        const auto reg = wideRegs.find(v->offset);
        if (reg != wideRegs.end()) {
            std::vector<uint8_t> value = reg->second;
            value.resize(static_cast<size_t>(v->size), 0);
            return value;
        }
    }
    if (v->kind == Varnode::CONST) {
        std::vector<uint8_t> value(static_cast<size_t>(v->size), 0);
        std::memcpy(value.data(), &v->offset, std::min<size_t>(8, value.size()));
        return value;
    }
    return std::nullopt;
}

std::optional<uint64_t> PcodeEvaluator::varnodeValue(uint64_t id) const {
    auto it = vals_.find(id);
    if (it != vals_.end()) return it->second;
    const Varnode* v = insn_.find(id);
    if (!v) return std::nullopt;
    if (v->kind == Varnode::CONST) return v->offset;
    if (v->kind == Varnode::REGISTER) {
        auto r = regs.find(v->offset);
        if (r != regs.end()) return r->second;
    }
    return std::nullopt;
}

std::optional<uint64_t> PcodeEvaluator::regValue(uint64_t offset) const {
    for (const auto& kv : vals_) {
        const Varnode* v = insn_.find(kv.first);
        if (v && v->kind == Varnode::REGISTER && v->offset == offset &&
            kv.second.has_value())
            return kv.second;
    }
    auto r = regs.find(offset);
    if (r != regs.end()) return r->second;
    return std::nullopt;
}

std::optional<uint64_t> PcodeEvaluator::evalOp(const PcodeOp& op) {
    const Varnode* vo = insn_.find(op.out);
    auto in = [&](uint64_t id) -> std::optional<uint64_t> {
        return varnodeValue(id);
    };
    auto dst = [&]() { return vo ? vo->size : 0; };
    auto floating = [&](uint64_t id) -> std::optional<uint64_t> {
        if (auto scalar = in(id)) return scalar;
        auto wide = wideValue(id);
        if (!wide || wide->empty()) return std::nullopt;
        uint64_t low = 0;
        std::memcpy(&low, wide->data(), std::min<size_t>(8, wide->size()));
        return low;
    };

    switch (op.op) {
    case POp::COPY: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        const int bits = dst() * 8;
        return bits > 0 && bits < 64 ? (*a & ((1ULL << bits) - 1)) : *a;
    }

    case POp::LOAD: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        const Varnode* v = insn_.find(op.out);
        const int sz = v ? v->size : 0;
        uint64_t val = 0;
        for (int i = 0; i < sz; ++i) {
            auto it = ram.find(*a + i);
            if (it == ram.end()) return std::nullopt;
            val |= static_cast<uint64_t>(it->second) << (8 * i);
        }
        return val;
    }
    case POp::STORE: {
        auto a = in(op.in0), v = in(op.in2);
        if (!a || !v) return std::nullopt;
        const Varnode* vs = insn_.find(op.in2);
        const int sz = vs ? vs->size : 0;
        for (int i = 0; i < sz; ++i)
            ram[*a + i] = static_cast<uint8_t>((*v >> (8 * i)) & 0xFF);
        return std::nullopt;
    }

    case POp::BRANCH:
        lastBranch_ = in(op.in0);
        return std::nullopt;
    case POp::CBRANCH: {
        auto t = in(op.in0), c = in(op.in1);
        lastBranch_ = t;
        branchTaken_ = c.has_value() && *c != 0;
        return std::nullopt;
    }
    case POp::BRANCHIND:
        lastBranch_ = in(op.in0);
        return std::nullopt;
    case POp::CALL:
    case POp::CALLIND:
        return std::nullopt;
    case POp::RETURN:
        return std::nullopt;

    case POp::INT_EQUAL: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bytes = va ? va->size : 8;
        return std::optional<uint64_t>(maskVal(*a, bytes) == maskVal(*b, bytes));
    }
    case POp::INT_NOTEQUAL: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bytes = va ? va->size : 8;
        return std::optional<uint64_t>(maskVal(*a, bytes) != maskVal(*b, bytes));
    }
    case POp::INT_LESS: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
        return std::optional<uint64_t>((*a & mask) < (*b & mask));
    }
    case POp::INT_SLESS: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const int64_t x = static_cast<int64_t>(sextVal(*a, bits));
        const int64_t y = static_cast<int64_t>(sextVal(*b, bits));
        return std::optional<uint64_t>(x < y);
    }
    case POp::INT_LESSEQUAL: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
        return std::optional<uint64_t>((*a & mask) <= (*b & mask));
    }
    case POp::INT_SLESSEQUAL: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const int64_t x = static_cast<int64_t>(sextVal(*a, bits));
        const int64_t y = static_cast<int64_t>(sextVal(*b, bits));
        return std::optional<uint64_t>(x <= y);
    }

    case POp::INT_ZEXT: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        const Varnode* vs = insn_.find(op.in0);
        const int bits = (vs ? vs->size : 8) * 8;
        const uint64_t mask = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
        return *a & mask;
    }
    case POp::INT_SEXT: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        const Varnode* vs = insn_.find(op.in0);
        return sextVal(*a, (vs ? vs->size : 8) * 8);
    }

    case POp::INT_ADD: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        uint64_t r = *a + *b;
        if (dst()) r &= (dst() * 8 >= 64) ? ~0ULL
                                          : ((1ULL << (dst() * 8)) - 1);
        return r;
    }
    case POp::INT_SUB: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        uint64_t r = *a - *b;
        if (dst()) r &= (dst() * 8 >= 64) ? ~0ULL
                                          : ((1ULL << (dst() * 8)) - 1);
        return r;
    }
    case POp::INT_NEGATE: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        return maskVal(uint64_t{0} - *a, dst());
    }
    case POp::INT_XOR: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(maskVal(*a ^ *b, dst()))
                        : std::nullopt;
    }
    case POp::INT_AND: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(maskVal(*a & *b, dst()))
                        : std::nullopt;
    }
    case POp::INT_OR: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(maskVal(*a | *b, dst()))
                        : std::nullopt;
    }
    case POp::INT_LEFT: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        uint64_t r = *b < 64 ? (*a << *b) : 0;
        if (dst()) r &= (dst() * 8 >= 64) ? ~0ULL
                                          : ((1ULL << (dst() * 8)) - 1);
        return r;
    }
    case POp::INT_RIGHT: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const uint64_t value = maskVal(*a, va ? va->size : 8);
        return std::optional<uint64_t>(*b < 64 ? (value >> *b) : 0);
    }
    case POp::INT_SRIGHT: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* vs = insn_.find(op.in0);
        const int bits = (vs ? vs->size : 8) * 8;
        if (*b >= 64) return 0;
        const int64_t s = static_cast<int64_t>(sextVal(*a, bits));
        return std::optional<uint64_t>(maskVal(
            static_cast<uint64_t>(s >> *b), dst()));
    }
    case POp::INT_MULT: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        uint64_t r = *a * *b;
        if (dst()) r &= (dst() * 8 >= 64) ? ~0ULL
                                          : ((1ULL << (dst() * 8)) - 1);
        return r;
    }
    case POp::INT_DIV: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b || *b == 0) return std::nullopt;
        return *a / *b;
    }
    case POp::INT_SDIV: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b || *b == 0) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const int64_t x = static_cast<int64_t>(sextVal(*a, bits));
        const int64_t y = static_cast<int64_t>(sextVal(*b, bits));
        if (y == -1 && x == INT64_MIN) return std::optional<uint64_t>(x);
        return std::optional<uint64_t>(static_cast<uint64_t>(x / y));
    }
    case POp::INT_REM: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b || *b == 0) return std::nullopt;
        return *a % *b;
    }
    case POp::INT_SREM: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b || *b == 0) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const int64_t x = static_cast<int64_t>(sextVal(*a, bits));
        const int64_t y = static_cast<int64_t>(sextVal(*b, bits));
        if (y == -1 && x == INT64_MIN) return std::optional<uint64_t>(0);
        return std::optional<uint64_t>(static_cast<uint64_t>(x % y));
    }
    case POp::INT_CARRY:
    case POp::INT_SCARRY:
    case POp::INT_SBORROW: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
        const uint64_t x = *a & mask, y = *b & mask;
        if (op.op == POp::INT_CARRY)
            return bits >= 64 ? std::optional<uint64_t>(x > ~y)
                              : std::optional<uint64_t>((x + y) > mask);
        const uint64_t sign = 1ULL << (bits - 1);
        const uint64_t r = op.op == POp::INT_SCARRY ? (x + y) & mask
                                                    : (x - y) & mask;
        if (op.op == POp::INT_SCARRY)
            return std::optional<uint64_t>(((~(x ^ y) & (x ^ r)) & sign) != 0);
        return std::optional<uint64_t>((((x ^ y) & (x ^ r)) & sign) != 0);
    }
    case POp::INT_PARITY: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        uint8_t x = static_cast<uint8_t>(*a);
        x ^= static_cast<uint8_t>(x >> 4);
        x ^= static_cast<uint8_t>(x >> 2);
        x ^= static_cast<uint8_t>(x >> 1);
        return std::optional<uint64_t>((x & 1U) == 0);
    }
    case POp::INT_POPCOUNT:
    case POp::INT_COUNT_LEADING_ZERO:
    case POp::INT_COUNT_TRAILING_ZERO: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const uint64_t x = maskVal(*a, va ? va->size : 8);
        if (op.op == POp::INT_POPCOUNT) {
            uint64_t v = x, count = 0;
            while (v) { v &= v - 1; ++count; }
            return count;
        }
        if (x == 0) return static_cast<uint64_t>(bits);
        uint64_t count = 0;
        if (op.op == POp::INT_COUNT_TRAILING_ZERO) {
            uint64_t v = x;
            while ((v & 1) == 0) { ++count; v >>= 1; }
        } else {
            uint64_t bit = 1ULL << (bits - 1);
            while ((x & bit) == 0) { ++count; bit >>= 1; }
        }
        return count;
    }
    case POp::INT_MULT_OVERFLOW:
    case POp::INT_SMULT_OVERFLOW: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* va = insn_.find(op.in0);
        const int bits = (va ? va->size : 8) * 8;
        const uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
        if (op.op == POp::INT_MULT_OVERFLOW) {
            const uint64_t x = *a & mask, y = *b & mask;
            return y != 0 && x > mask / y;
        }
        const int64_t x = static_cast<int64_t>(sextVal(*a, bits));
        const int64_t y = static_cast<int64_t>(sextVal(*b, bits));
        const int64_t maximum = bits >= 64 ? INT64_MAX
                                           : static_cast<int64_t>((1ULL << (bits - 1)) - 1);
        const int64_t minimum = bits >= 64 ? INT64_MIN
                                           : -static_cast<int64_t>(1ULL << (bits - 1));
        if (x == 0 || y == 0) return 0;
        if (x == -1) return y == minimum;
        if (y == -1) return x == minimum;
        if (x > 0)
            return y > 0 ? x > maximum / y : y < minimum / x;
        return y > 0 ? x < minimum / y : x < maximum / y;
    }
    case POp::FLOAT_INT2FLOAT: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        const Varnode* source = insn_.find(op.in0);
        const int sourceBits = (source ? source->size : 8) * 8;
        const int64_t signedValue = static_cast<int64_t>(sextVal(*a, sourceBits));
        const int floatBits = op.aux & 0x7fff;
        if (floatBits == 32) {
            const float converted = static_cast<float>(signedValue);
            uint32_t bits = 0;
            std::memcpy(&bits, &converted, sizeof(bits));
            return bits;
        }
        if (floatBits == 64) {
            const double converted = static_cast<double>(signedValue);
            uint64_t bits = 0;
            std::memcpy(&bits, &converted, sizeof(bits));
            return bits;
        }
        return std::nullopt;
    }
    case POp::FLOAT_FLOAT2INT: {
        auto source = floating(op.in0);
        if (!source || !vo) return std::nullopt;
        const int floatBits = op.aux & 0x7fff;
        long double value = 0;
        if (floatBits == 32) {
            const uint32_t bits = static_cast<uint32_t>(*source);
            float converted = 0;
            std::memcpy(&converted, &bits, sizeof(bits));
            value = converted;
        } else if (floatBits == 64) {
            double converted = 0;
            const uint64_t bits = *source;
            std::memcpy(&converted, &bits, sizeof(bits));
            value = converted;
        } else {
            return std::nullopt;
        }
        const long double rounded = (op.aux & 0x8000) ? std::trunc(value)
                                                       : std::nearbyint(value);
        const int integerBits = vo->size * 8;
        const long double limit = std::ldexp(1.0L, integerBits - 1);
        const uint64_t indefinite = integerBits >= 64 ? (1ULL << 63)
                                                       : (1ULL << (integerBits - 1));
        if (!std::isfinite(rounded) || rounded < -limit || rounded >= limit)
            return indefinite;
        return maskVal(static_cast<uint64_t>(static_cast<int64_t>(rounded)), vo->size);
    }
    case POp::FLOAT_FLOAT2FLOAT: {
        auto source = floating(op.in0);
        if (!source) return std::nullopt;
        const int sourceBits = op.aux & 0xff;
        const int destinationBits = (op.aux >> 8) & 0x7f;
        if (sourceBits == 32 && destinationBits == 64) {
            const uint32_t bits = static_cast<uint32_t>(*source);
            float input = 0;
            std::memcpy(&input, &bits, sizeof(bits));
            const double output = static_cast<double>(input);
            uint64_t result = 0;
            std::memcpy(&result, &output, sizeof(result));
            return result;
        }
        if (sourceBits == 64 && destinationBits == 32) {
            double input = 0;
            const uint64_t bits = *source;
            std::memcpy(&input, &bits, sizeof(bits));
            const float output = static_cast<float>(input);
            uint32_t result = 0;
            std::memcpy(&result, &output, sizeof(result));
            return result;
        }
        return std::nullopt;
    }
    case POp::FLOAT_EQUAL:
    case POp::FLOAT_NOTEQUAL:
    case POp::FLOAT_LESS:
    case POp::FLOAT_LESSEQUAL:
    case POp::FLOAT_NAN:
    case POp::FLOAT_ADD:
    case POp::FLOAT_SUB:
    case POp::FLOAT_MULT:
    case POp::FLOAT_DIV:
    case POp::FLOAT_NEG:
    case POp::FLOAT_ABS:
    case POp::FLOAT_SQRT:
    case POp::FLOAT_MIN:
    case POp::FLOAT_MAX: {
        auto a = floating(op.in0);
        auto b = floating(op.in1);
        if (!a || (op.op != POp::FLOAT_NEG && op.op != POp::FLOAT_ABS &&
                   op.op != POp::FLOAT_SQRT && op.op != POp::FLOAT_NAN && !b))
            return std::nullopt;
        const int laneBits = (op.aux & 0x7fff) ? (op.aux & 0x7fff) : 64;
        if (laneBits == 32) {
            uint32_t ab = static_cast<uint32_t>(*a), bb = static_cast<uint32_t>(b.value_or(0));
            float x = 0, y = 0, z = 0;
            std::memcpy(&x, &ab, 4); std::memcpy(&y, &bb, 4);
            switch (op.op) {
            case POp::FLOAT_EQUAL: return !std::isnan(x) && !std::isnan(y) && x == y;
            case POp::FLOAT_NOTEQUAL: return std::isnan(x) || std::isnan(y) || x != y;
            case POp::FLOAT_LESS: return !std::isnan(x) && !std::isnan(y) && x < y;
            case POp::FLOAT_LESSEQUAL: return !std::isnan(x) && !std::isnan(y) && x <= y;
            case POp::FLOAT_NAN: return std::isnan(x) || (b && std::isnan(y));
            case POp::FLOAT_ADD: z = x + y; break;
            case POp::FLOAT_SUB: z = x - y; break;
            case POp::FLOAT_MULT: z = x * y; break;
            case POp::FLOAT_DIV: z = x / y; break;
            case POp::FLOAT_NEG: z = -x; break;
            case POp::FLOAT_ABS: z = std::fabs(x); break;
            case POp::FLOAT_SQRT: z = std::sqrt(x); break;
            case POp::FLOAT_MIN: z = (std::isnan(x) || std::isnan(y)) ? y
                                          : (x < y ? x : y); break;
            case POp::FLOAT_MAX: z = (std::isnan(x) || std::isnan(y)) ? y
                                          : (x > y ? x : y); break;
            default: break;
            }
            uint32_t bits = 0; std::memcpy(&bits, &z, 4); return bits;
        }
        double x = 0, y = 0, z = 0;
        const uint64_t ab = *a, bb = b.value_or(0);
        std::memcpy(&x, &ab, 8); std::memcpy(&y, &bb, 8);
        switch (op.op) {
        case POp::FLOAT_EQUAL: return !std::isnan(x) && !std::isnan(y) && x == y;
        case POp::FLOAT_NOTEQUAL: return std::isnan(x) || std::isnan(y) || x != y;
        case POp::FLOAT_LESS: return !std::isnan(x) && !std::isnan(y) && x < y;
        case POp::FLOAT_LESSEQUAL: return !std::isnan(x) && !std::isnan(y) && x <= y;
        case POp::FLOAT_NAN: return std::isnan(x) || (b && std::isnan(y));
        case POp::FLOAT_ADD: z = x + y; break;
        case POp::FLOAT_SUB: z = x - y; break;
        case POp::FLOAT_MULT: z = x * y; break;
        case POp::FLOAT_DIV: z = x / y; break;
        case POp::FLOAT_NEG: z = -x; break;
        case POp::FLOAT_ABS: z = std::fabs(x); break;
        case POp::FLOAT_SQRT: z = std::sqrt(x); break;
        case POp::FLOAT_MIN: z = (std::isnan(x) || std::isnan(y)) ? y
                                      : (x < y ? x : y); break;
        case POp::FLOAT_MAX: z = (std::isnan(x) || std::isnan(y)) ? y
                                      : (x > y ? x : y); break;
        default: break;
        }
        uint64_t bits = 0; std::memcpy(&bits, &z, 8); return bits;
    }

    case POp::BOOL_NEGATE: {
        auto a = in(op.in0);
        return a ? std::optional<uint64_t>(*a ? 0 : 1) : std::nullopt;
    }
    case POp::BOOL_XOR: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        return std::optional<uint64_t>((*a != 0) ^ (*b != 0));
    }
    case POp::BOOL_AND: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        return std::optional<uint64_t>((*a != 0) && (*b != 0));
    }
    case POp::BOOL_OR: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        return std::optional<uint64_t>((*a != 0) || (*b != 0));
    }

    case POp::PIECE: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* vb = insn_.find(op.in1);
        const int shift = (vb ? vb->size : 8) * 8;
        return (shift >= 64 ? 0 : (*a << shift)) | *b;
    }

    case POp::SELECT: {
        auto c = in(op.in0);
        if (!c) return std::nullopt;
        return in(*c ? op.in1 : op.in2);
    }
    case POp::SUBPIECE: {
        auto a = in(op.in0);
        const std::optional<uint64_t> off =
            op.in1 == 0 ? std::optional<uint64_t>(0) : in(op.in1);
        if (!a || !off) return std::nullopt;
        const int sz = dst();
        if (sz <= 0 || *off >= 8) return std::optional<uint64_t>(0);
        const uint64_t shifted = *a >> (static_cast<unsigned>(*off) * 8);
        const uint64_t mask = sz >= 8 ? ~0ULL : ((1ULL << (sz * 8)) - 1);
        return shifted & mask;
    }

    case POp::UNIMPLEMENTED:
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> PcodeEvaluator::evalWideOp(const PcodeOp& op) {
    const Varnode* out = insn_.find(op.out);
    const size_t size = out ? static_cast<size_t>(out->size) : 0;
    if (op.op == POp::LOAD) {
        auto address = varnodeValue(op.in0);
        if (!address || !out) return std::nullopt;
        std::vector<uint8_t> value(size);
        for (size_t i = 0; i < size; ++i) {
            const auto byte = ram.find(*address + i);
            if (byte == ram.end()) return std::nullopt;
            value[i] = byte->second;
        }
        return value;
    }
    if (op.op == POp::STORE) {
        auto address = varnodeValue(op.in0);
        auto value = wideValue(op.in2);
        if (!address || !value) return std::nullopt;
        for (size_t i = 0; i < value->size(); ++i) ram[*address + i] = (*value)[i];
        return std::nullopt;
    }
    if (op.op == POp::FLOAT_INT2FLOAT) {
        auto input = varnodeValue(op.in0);
        if (!input) return std::nullopt;
        const Varnode* source = insn_.find(op.in0);
        const int sourceBits = (source ? source->size : 8) * 8;
        const int64_t signedValue = static_cast<int64_t>(sextVal(*input, sourceBits));
        std::vector<uint8_t> result(size, 0);
        if (auto base = wideValue(op.in1)) {
            result = std::move(*base);
            result.resize(size, 0);
        }
        const int floatBits = op.aux & 0x7fff;
        if (floatBits == 32) {
            const float converted = static_cast<float>(signedValue);
            std::memcpy(result.data(), &converted, sizeof(converted));
        } else if (floatBits == 64) {
            const double converted = static_cast<double>(signedValue);
            std::memcpy(result.data(), &converted, sizeof(converted));
        } else {
            return std::nullopt;
        }
        return result;
    }
    if (op.op == POp::FLOAT_FLOAT2FLOAT) {
        auto input = wideValue(op.in0);
        if (!input) return std::nullopt;
        std::vector<uint8_t> result(size, 0);
        if (auto base = wideValue(op.in1)) {
            result = std::move(*base);
            result.resize(size, 0);
        }
        const int sourceBits = op.aux & 0xff;
        const int destinationBits = (op.aux >> 8) & 0x7f;
        if (sourceBits == 32 && destinationBits == 64) {
            float sourceValue = 0;
            std::memcpy(&sourceValue, input->data(), sizeof(sourceValue));
            const double converted = static_cast<double>(sourceValue);
            std::memcpy(result.data(), &converted, sizeof(converted));
        } else if (sourceBits == 64 && destinationBits == 32) {
            double sourceValue = 0;
            std::memcpy(&sourceValue, input->data(), sizeof(sourceValue));
            const float converted = static_cast<float>(sourceValue);
            std::memcpy(result.data(), &converted, sizeof(converted));
        } else {
            return std::nullopt;
        }
        return result;
    }
    auto a = wideValue(op.in0);
    auto b = wideValue(op.in1);
    if (!a) return std::nullopt;
    a->resize(size, 0);
    if (op.op == POp::COPY) return a;
    if (op.op == POp::INT_AND || op.op == POp::INT_OR || op.op == POp::INT_XOR) {
        if (!b) return std::nullopt;
        b->resize(size, 0);
        for (size_t i = 0; i < size; ++i) {
            if (op.op == POp::INT_AND) (*a)[i] &= (*b)[i];
            else if (op.op == POp::INT_OR) (*a)[i] |= (*b)[i];
            else (*a)[i] ^= (*b)[i];
        }
        return a;
    }
    if (op.op == POp::INT_ADD || op.op == POp::INT_SUB ||
        op.op == POp::INT_MULT) {
        if (!b) return std::nullopt;
        b->resize(size, 0);
        const int laneBits = op.aux ? op.aux : 8;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        if (!laneBytes || laneBytes > 8 || size % laneBytes) return std::nullopt;
        const uint64_t laneMask = laneBytes == 8 ? ~0ULL
                                                  : ((1ULL << laneBits) - 1);
        for (size_t at = 0; at < size; at += laneBytes) {
            uint64_t x = 0, y = 0, z = 0;
            std::memcpy(&x, a->data() + at, laneBytes);
            std::memcpy(&y, b->data() + at, laneBytes);
            if (op.op == POp::INT_ADD) z = x + y;
            else if (op.op == POp::INT_SUB) z = x - y;
            else z = x * y;
            z &= laneMask;
            std::memcpy(a->data() + at, &z, laneBytes);
        }
        return a;
    }
    const bool unary = op.op == POp::FLOAT_NEG || op.op == POp::FLOAT_ABS ||
                       op.op == POp::FLOAT_SQRT;
    if (!unary && !b) return std::nullopt;
    if (b) b->resize(size, 0);
    const int laneBits = (op.aux & 0x7fff) ? (op.aux & 0x7fff) : 32;
    const size_t laneBytes = static_cast<size_t>(laneBits / 8);
    if ((laneBytes != 4 && laneBytes != 8) || size % laneBytes) return std::nullopt;
    const bool scalar = (op.aux & 0x8000) != 0;
    const size_t lanes = scalar ? 1 : size / laneBytes;
    std::vector<uint8_t> source = *a;
    if (scalar && b && unary) {
        std::vector<uint8_t> base = *b;
        base.resize(size, 0);
        *a = std::move(base);
    }
    for (size_t lane = 0; lane < lanes; ++lane) {
        const size_t at = lane * laneBytes;
        if (laneBytes == 4) {
            float x = 0, y = 0, z = 0;
            std::memcpy(&x, source.data() + at, 4);
            if (b) std::memcpy(&y, b->data() + at, 4);
            switch (op.op) {
            case POp::FLOAT_ADD: z = x + y; break;
            case POp::FLOAT_SUB: z = x - y; break;
            case POp::FLOAT_MULT: z = x * y; break;
            case POp::FLOAT_DIV: z = x / y; break;
            case POp::FLOAT_NEG: z = -x; break;
            case POp::FLOAT_ABS: z = std::fabs(x); break;
            case POp::FLOAT_SQRT: z = std::sqrt(x); break;
            case POp::FLOAT_MIN: z = (std::isnan(x) || std::isnan(y)) ? y
                                          : (x < y ? x : y); break;
            case POp::FLOAT_MAX: z = (std::isnan(x) || std::isnan(y)) ? y
                                          : (x > y ? x : y); break;
            default: return std::nullopt;
            }
            std::memcpy(a->data() + at, &z, 4);
        } else {
            double x = 0, y = 0, z = 0;
            std::memcpy(&x, source.data() + at, 8);
            if (b) std::memcpy(&y, b->data() + at, 8);
            switch (op.op) {
            case POp::FLOAT_ADD: z = x + y; break;
            case POp::FLOAT_SUB: z = x - y; break;
            case POp::FLOAT_MULT: z = x * y; break;
            case POp::FLOAT_DIV: z = x / y; break;
            case POp::FLOAT_NEG: z = -x; break;
            case POp::FLOAT_ABS: z = std::fabs(x); break;
            case POp::FLOAT_SQRT: z = std::sqrt(x); break;
            case POp::FLOAT_MIN: z = (std::isnan(x) || std::isnan(y)) ? y
                                          : (x < y ? x : y); break;
            case POp::FLOAT_MAX: z = (std::isnan(x) || std::isnan(y)) ? y
                                          : (x > y ? x : y); break;
            default: return std::nullopt;
            }
            std::memcpy(a->data() + at, &z, 8);
        }
    }
    return a;
}

} // namespace centrifuge
