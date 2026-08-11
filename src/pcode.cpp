// centrifuge - a Ghidra reimplementation in C++17
// pcode.cpp - p-code names + interpreter
#include "centrifuge/pcode.hpp"

#include <algorithm>
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
    case POp::TRAP: return "TRAP";
    case POp::SYSCALL: return "SYSCALL";
    case POp::MEMORY_BARRIER: return "MEMORY_BARRIER";
    case POp::CACHE_HINT: return "CACHE_HINT";
    case POp::X86_XSTATE_SAVE: return "X86_XSTATE_SAVE";
    case POp::X86_XSTATE_RESTORE: return "X86_XSTATE_RESTORE";
    case POp::X86_SYSTEM: return "X86_SYSTEM";
    case POp::X86_STRING: return "X86_STRING";
    case POp::X86_DIVIDE: return "X86_DIVIDE";
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
    case POp::INT_NOT: return "INT_NOT";
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
    case POp::INT_PDEP: return "INT_PDEP";
    case POp::INT_PEXT: return "INT_PEXT";
    case POp::INT_BSWAP: return "INT_BSWAP";
    case POp::INT_CRC32C: return "INT_CRC32C";
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
    case POp::FLOAT_ROUND: return "FLOAT_ROUND";
    case POp::FLOAT_SIN: return "FLOAT_SIN";
    case POp::FLOAT_COS: return "FLOAT_COS";
    case POp::FLOAT_TAN: return "FLOAT_TAN";
    case POp::FLOAT_ATAN2: return "FLOAT_ATAN2";
    case POp::FLOAT_LOG2: return "FLOAT_LOG2";
    case POp::FLOAT_EXP2: return "FLOAT_EXP2";
    case POp::FLOAT_REMAINDER: return "FLOAT_REMAINDER";
    case POp::FLOAT_SCALE: return "FLOAT_SCALE";
    case POp::FLOAT_INT2FLOAT: return "FLOAT_INT2FLOAT";
    case POp::FLOAT_FLOAT2INT: return "FLOAT_FLOAT2INT";
    case POp::FLOAT_FLOAT2FLOAT: return "FLOAT_FLOAT2FLOAT";
    case POp::SIMD_MASK: return "SIMD_MASK";
    case POp::SIMD_COMPARE: return "SIMD_COMPARE";
    case POp::SIMD_COMPARE_MASK: return "SIMD_COMPARE_MASK";
    case POp::SIMD_MOVEMASK: return "SIMD_MOVEMASK";
    case POp::SIMD_ADDSUB: return "SIMD_ADDSUB";
    case POp::SIMD_BLEND: return "SIMD_BLEND";
    case POp::SIMD_FP_COMPARE: return "SIMD_FP_COMPARE";
    case POp::SIMD_COMPARE_CHECK: return "SIMD_COMPARE_CHECK";
    case POp::SIMD_HORIZONTAL: return "SIMD_HORIZONTAL";
    case POp::SIMD_INT2FLOAT: return "SIMD_INT2FLOAT";
    case POp::SIMD_FLOAT2INT: return "SIMD_FLOAT2INT";
    case POp::SIMD_FLOAT2FLOAT: return "SIMD_FLOAT2FLOAT";
    case POp::SIMD_DOT_PRODUCT: return "SIMD_DOT_PRODUCT";
    case POp::SIMD_ABS: return "SIMD_ABS";
    case POp::SIMD_INT_HORIZONTAL: return "SIMD_INT_HORIZONTAL";
    case POp::SIMD_STRING_COMPARE: return "SIMD_STRING_COMPARE";
    case POp::SIMD_STRING_MASK: return "SIMD_STRING_MASK";
    case POp::SIMD_MULTIPLY: return "SIMD_MULTIPLY";
    case POp::SIMD_SIGN: return "SIMD_SIGN";
    case POp::SIMD_BYTE_SHIFT: return "SIMD_BYTE_SHIFT";
    case POp::SIMD_TEST: return "SIMD_TEST";
    case POp::SIMD_APPROX: return "SIMD_APPROX";
    case POp::SIMD_ROUND: return "SIMD_ROUND";
    case POp::SIMD_PERMUTE128: return "SIMD_PERMUTE128";
    case POp::SIMD_EXTEND: return "SIMD_EXTEND";
    case POp::SIMD_ZERO_UPPER: return "SIMD_ZERO_UPPER";
    case POp::SIMD_SATURATE: return "SIMD_SATURATE";
    case POp::SIMD_UNPACK: return "SIMD_UNPACK";
    case POp::SIMD_PACK: return "SIMD_PACK";
    case POp::SIMD_SHUFFLE: return "SIMD_SHUFFLE";
    case POp::SIMD_SHIFT: return "SIMD_SHIFT";
    case POp::SIMD_EXTRACT: return "SIMD_EXTRACT";
    case POp::SIMD_INSERT: return "SIMD_INSERT";
    case POp::SIMD_BROADCAST: return "SIMD_BROADCAST";
    case POp::SIMD_GATHER: return "SIMD_GATHER";
    case POp::SIMD_SCATTER: return "SIMD_SCATTER";
    case POp::SIMD_AVERAGE: return "SIMD_AVERAGE";
    case POp::SIMD_MINMAX: return "SIMD_MINMAX";
    case POp::SIMD_SAD: return "SIMD_SAD";
    case POp::AES_ENC: return "AES_ENC";
    case POp::AES_DEC: return "AES_DEC";
    case POp::AES_IMC: return "AES_IMC";
    case POp::AES_KEYGEN: return "AES_KEYGEN";
    case POp::GF2P8_MUL: return "GF2P8_MUL";
    case POp::GF2P8_AFFINE: return "GF2P8_AFFINE";
    case POp::GF2P8_AFFINE_INV: return "GF2P8_AFFINE_INV";
    case POp::CARRYLESS_MULT: return "CARRYLESS_MULT";
    case POp::SHA1_MSG1: return "SHA1_MSG1";
    case POp::SHA1_MSG2: return "SHA1_MSG2";
    case POp::SHA1_NEXTE: return "SHA1_NEXTE";
    case POp::SHA1_RNDS4: return "SHA1_RNDS4";
    case POp::SHA256_MSG1: return "SHA256_MSG1";
    case POp::SHA256_MSG2: return "SHA256_MSG2";
    case POp::SHA256_RNDS2: return "SHA256_RNDS2";
    case POp::X86_GUARD: return "X86_GUARD";
    case POp::X87_REQUIRE: return "X87_REQUIRE";
    case POp::X87_PUSH: return "X87_PUSH";
    case POp::X87_POP: return "X87_POP";
    case POp::X87_FREE: return "X87_FREE";
    case POp::X87_TAG: return "X87_TAG";
    case POp::X87_EXAMINE: return "X87_EXAMINE";
    case POp::X87_ROTATE: return "X87_ROTATE";
    case POp::X87_CONSTANT: return "X87_CONSTANT";
    case POp::X87_COMPARE_CHECK: return "X87_COMPARE_CHECK";
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

std::optional<long double> decodeFloatValue(const std::vector<uint8_t>& bytes,
                                            int bits) {
    if (bits == 32 && bytes.size() >= 4) {
        float value = 0;
        std::memcpy(&value, bytes.data(), 4);
        return static_cast<long double>(value);
    }
    if (bits == 64 && bytes.size() >= 8) {
        double value = 0;
        std::memcpy(&value, bytes.data(), 8);
        return static_cast<long double>(value);
    }
    if (bits != 80 || bytes.size() < 10) return std::nullopt;
    uint64_t significand = 0;
    uint16_t signExponent = 0;
    std::memcpy(&significand, bytes.data(), 8);
    std::memcpy(&signExponent, bytes.data() + 8, 2);
    const bool negative = (signExponent & 0x8000U) != 0;
    const unsigned exponent = signExponent & 0x7fffU;
    long double value = 0;
    if (exponent == 0x7fffU) {
        value = significand == 0x8000000000000000ULL
                    ? std::numeric_limits<long double>::infinity()
                    : std::numeric_limits<long double>::quiet_NaN();
    } else if (exponent != 0 || significand != 0) {
        const int unbiased = exponent ? static_cast<int>(exponent) - 16383
                                      : 1 - 16383;
        value = std::ldexp(static_cast<long double>(significand),
                           unbiased - 63);
    }
    return negative ? -value : value;
}

std::vector<uint8_t> encodeFloatValue(long double value, int bits) {
    std::vector<uint8_t> result(static_cast<size_t>(bits / 8), 0);
    if (bits == 32) {
        const float converted = static_cast<float>(value);
        std::memcpy(result.data(), &converted, 4);
    } else if (bits == 64) {
        const double converted = static_cast<double>(value);
        std::memcpy(result.data(), &converted, 8);
    } else if (bits == 80) {
        const bool negative = std::signbit(value);
        const long double magnitude = std::fabs(value);
        uint64_t significand = 0;
        uint16_t exponent = 0;
        if (std::isnan(magnitude)) {
            exponent = 0x7fffU;
            significand = 0xc000000000000000ULL;
        } else if (std::isinf(magnitude)) {
            exponent = 0x7fffU;
            significand = 0x8000000000000000ULL;
        } else if (magnitude != 0) {
            int binaryExponent = 0;
            const long double fraction = std::frexp(magnitude, &binaryExponent);
            const int encodedExponent = binaryExponent - 1 + 16383;
            if (encodedExponent > 0) {
                exponent = static_cast<uint16_t>(std::min(encodedExponent, 0x7fff));
                significand = static_cast<uint64_t>(std::ldexp(fraction, 64));
            } else {
                significand = static_cast<uint64_t>(
                    std::ldexp(magnitude, 16382 + 63));
            }
        }
        const uint16_t signExponent = static_cast<uint16_t>(
            exponent | (negative ? 0x8000U : 0));
        std::memcpy(result.data(), &significand, 8);
        std::memcpy(result.data() + 8, &signExponent, 2);
    }
    return result;
}

uint8_t gf256Multiply(uint8_t left, uint8_t right) {
    uint8_t result = 0;
    while (right) {
        if (right & 1U) result ^= left;
        const bool high = (left & 0x80U) != 0;
        left = static_cast<uint8_t>(left << 1);
        if (high) left ^= 0x1bU;
        right = static_cast<uint8_t>(right >> 1);
    }
    return result;
}

uint8_t gf256Inverse(uint8_t value) {
    if (value == 0) return 0;
    uint8_t result = 1;
    uint8_t base = value;
    unsigned exponent = 254;
    while (exponent) {
        if (exponent & 1U) result = gf256Multiply(result, base);
        base = gf256Multiply(base, base);
        exponent >>= 1;
    }
    return result;
}

uint8_t parity8(uint8_t value) {
    value ^= static_cast<uint8_t>(value >> 4);
    value &= 0x0fU;
    return static_cast<uint8_t>((0x6996U >> value) & 1U);
}

uint32_t rotateLeft32(uint32_t value, unsigned count) {
    count &= 31U;
    return count ? (value << count) | (value >> (32U - count)) : value;
}

uint32_t rotateRight32(uint32_t value, unsigned count) {
    count &= 31U;
    return count ? (value >> count) | (value << (32U - count)) : value;
}

uint32_t readDword(const std::vector<uint8_t>& value, size_t lane) {
    uint32_t result = 0;
    if (lane * 4 + 4 <= value.size())
        std::memcpy(&result, value.data() + lane * 4, 4);
    return result;
}

void writeDword(std::vector<uint8_t>& value, size_t lane, uint32_t word) {
    if (lane * 4 + 4 <= value.size())
        std::memcpy(value.data() + lane * 4, &word, 4);
}

long double roundX87Precision(long double value, uint16_t control,
                              bool& inexact) {
    inexact = false;
    if (!std::isfinite(value) || value == 0) return value;
    const unsigned pc = (control >> 8) & 3U;
    const int precision = pc == 0 ? 24 : pc == 2 ? 53 : 64;
    int exponent = 0;
    const long double fraction = std::frexp(value, &exponent);
    const long double scaled = std::ldexp(fraction, precision);
    long double integral = 0;
    switch ((control >> 10) & 3U) {
    case 0: integral = std::nearbyint(scaled); break;
    case 1: integral = std::floor(scaled); break;
    case 2: integral = std::ceil(scaled); break;
    default: integral = std::trunc(scaled); break;
    }
    const long double rounded = std::ldexp(integral, exponent - precision);
    inexact = rounded != value;
    return rounded;
}

uint8_t aesSbox(uint8_t value) {
    uint8_t inverse = 0;
    if (value) {
        inverse = 1;
        uint8_t base = value;
        unsigned exponent = 254;
        while (exponent) {
            if (exponent & 1U) inverse = gf256Multiply(inverse, base);
            base = gf256Multiply(base, base);
            exponent >>= 1;
        }
    }
    auto rotate = [](uint8_t x, unsigned amount) {
        return static_cast<uint8_t>((x << amount) | (x >> (8 - amount)));
    };
    return static_cast<uint8_t>(inverse ^ rotate(inverse, 1) ^
                                rotate(inverse, 2) ^ rotate(inverse, 3) ^
                                rotate(inverse, 4) ^ 0x63U);
}

uint8_t aesInverseSbox(uint8_t value) {
    for (unsigned candidate = 0; candidate < 256; ++candidate)
        if (aesSbox(static_cast<uint8_t>(candidate)) == value)
            return static_cast<uint8_t>(candidate);
    return 0;
}

void aesShiftSub(uint8_t* state, bool inverse) {
    uint8_t original[16] = {};
    std::memcpy(original, state, sizeof(original));
    for (size_t column = 0; column < 4; ++column)
        for (size_t row = 0; row < 4; ++row) {
            const size_t sourceColumn = inverse
                                            ? (column + 4 - row) % 4
                                            : (column + row) % 4;
            const uint8_t value = original[row + sourceColumn * 4];
            state[row + column * 4] = inverse ? aesInverseSbox(value)
                                               : aesSbox(value);
        }
}

void aesMixColumns(uint8_t* state, bool inverse) {
    for (size_t column = 0; column < 4; ++column) {
        uint8_t* x = state + column * 4;
        const uint8_t a = x[0], b = x[1], c = x[2], d = x[3];
        if (!inverse) {
            x[0] = gf256Multiply(a, 2) ^ gf256Multiply(b, 3) ^ c ^ d;
            x[1] = a ^ gf256Multiply(b, 2) ^ gf256Multiply(c, 3) ^ d;
            x[2] = a ^ b ^ gf256Multiply(c, 2) ^ gf256Multiply(d, 3);
            x[3] = gf256Multiply(a, 3) ^ b ^ c ^ gf256Multiply(d, 2);
        } else {
            x[0] = gf256Multiply(a, 14) ^ gf256Multiply(b, 11) ^
                   gf256Multiply(c, 13) ^ gf256Multiply(d, 9);
            x[1] = gf256Multiply(a, 9) ^ gf256Multiply(b, 14) ^
                   gf256Multiply(c, 11) ^ gf256Multiply(d, 13);
            x[2] = gf256Multiply(a, 13) ^ gf256Multiply(b, 9) ^
                   gf256Multiply(c, 14) ^ gf256Multiply(d, 11);
            x[3] = gf256Multiply(a, 11) ^ gf256Multiply(b, 13) ^
                   gf256Multiply(c, 9) ^ gf256Multiply(d, 14);
        }
    }
}

} // namespace

void PcodeEvaluator::run() {
    vals_.clear();
    wideVals_.clear();
    lastBranch_.reset();
    branchTaken_ = false;
    suppressRemaining_ = false;
    fault.reset();
    for (const auto& op : insn_.ops) {
        if (fault || suppressRemaining_) break;
        const Varnode* out = insn_.find(op.out);
        const Varnode* storeValue = insn_.find(op.in2);
        const bool wide = (out && out->size > 8) ||
                          ((op.op == POp::STORE || op.op == POp::SIMD_SCATTER) &&
                           storeValue && storeValue->size > 8);
        if (wide) {
            auto value = evalWideOp(op);
            if (op.out) {
                wideVals_[op.out] = value;
                if (value && out && out->kind == Varnode::REGISTER)
                    wideRegs[out->offset] = *value;
                if (value && !value->empty()) {
                    uint64_t low = 0;
                    std::memcpy(&low, value->data(), std::min<size_t>(8, value->size()));
                    vals_[op.out] = low;
                }
            }
            continue;
        }
        std::optional<uint64_t> r = evalOp(op);
        if (op.out != 0) {
            vals_[op.out] = r;
            if (r && out && out->kind == Varnode::REGISTER)
                regs[out->offset] = *r;
        }
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
        const auto scalarReg = regs.find(v->offset);
        if (scalarReg != regs.end()) {
            std::vector<uint8_t> value(static_cast<size_t>(v->size), 0);
            std::memcpy(value.data(), &scalarReg->second,
                        std::min<size_t>(8, value.size()));
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
    case POp::TRAP:
    case POp::SYSCALL:
    case POp::MEMORY_BARRIER:
    case POp::CACHE_HINT:
        return std::nullopt;

    case POp::X86_XSTATE_SAVE:
    case POp::X86_XSTATE_RESTORE: {
        const auto address = in(op.in0);
        if (!address) return std::nullopt;
        const bool save = op.op == POp::X86_XSTATE_SAVE;
        const bool legacyOnly = op.aux == 0;
        const bool compacted = op.aux == 2 || op.aux == 3;
        const uint64_t requested = legacyOnly
            ? 3
            : ((regValue(16).value_or(0) << 32) |
               (regValue(0).value_or(0) & 0xffffffffULL));
        const uint64_t enabled = op.aux == 3 ? (xcr0 | xss) : xcr0;
        const uint64_t components = legacyOnly ? 3 : (requested & enabled);
        auto writeInteger = [&](size_t offset, uint64_t value, size_t bytes) {
            for (size_t byte = 0; byte < bytes; ++byte)
                ram[*address + offset + byte] =
                    static_cast<uint8_t>(value >> (byte * 8));
        };
        auto readInteger = [&](size_t offset, size_t bytes) {
            uint64_t value = 0;
            for (size_t byte = 0; byte < bytes; ++byte) {
                const auto found = ram.find(*address + offset + byte);
                if (found != ram.end())
                    value |= static_cast<uint64_t>(found->second) << (byte * 8);
            }
            return value;
        };
        auto writeBytes = [&](size_t offset, const std::vector<uint8_t>& value,
                              size_t sourceOffset, size_t bytes) {
            for (size_t byte = 0; byte < bytes; ++byte)
                ram[*address + offset + byte] =
                    sourceOffset + byte < value.size()
                        ? value[sourceOffset + byte] : 0;
        };
        auto readBytes = [&](size_t offset, std::vector<uint8_t>& value,
                             size_t destinationOffset, size_t bytes) {
            if (value.size() < destinationOffset + bytes)
                value.resize(destinationOffset + bytes, 0);
            for (size_t byte = 0; byte < bytes; ++byte) {
                const auto found = ram.find(*address + offset + byte);
                value[destinationOffset + byte] =
                    found == ram.end() ? 0 : found->second;
            }
        };
        if (save) {
            writeInteger(0, regValue(12416).value_or(0x037f), 2);
            writeInteger(2, regValue(12418).value_or(0), 2);
            writeInteger(4, regValue(12420).value_or(0xff), 1);
            writeInteger(24, regValue(12424).value_or(0x1f80), 4);
            for (size_t index = 0; index < 8; ++index)
                writeBytes(32 + index * 16,
                           wideRegs[12288 + index * 16], 0, 10);
            for (size_t index = 0; index < 16; ++index)
                writeBytes(160 + index * 16, wideRegs[index * 8], 0, 16);
            if (!legacyOnly) {
                writeInteger(512, components, 8);
                writeInteger(520, compacted ? (components | (1ULL << 63)) : 0,
                             8);
                size_t avxOffset = 576, opmaskOffset = 1088;
                size_t zmmHighOffset = 1152, high16Offset = 1664;
                if (compacted) {
                    avxOffset = 576;
                    opmaskOffset = avxOffset + 256;
                    zmmHighOffset = opmaskOffset + 64;
                    high16Offset = zmmHighOffset + 512;
                }
                if (components & (1ULL << 2))
                    for (size_t index = 0; index < 16; ++index)
                        writeBytes(avxOffset + index * 16,
                                   wideRegs[index * 8], 16, 16);
                if (components & (1ULL << 5))
                    for (size_t index = 0; index < 8; ++index)
                        writeInteger(opmaskOffset + index * 8,
                                     regValue(8192 + index * 8).value_or(0), 8);
                if (components & (1ULL << 6))
                    for (size_t index = 0; index < 16; ++index)
                        writeBytes(zmmHighOffset + index * 32,
                                   wideRegs[index * 8], 32, 32);
                if (components & (1ULL << 7))
                    for (size_t index = 16; index < 32; ++index)
                        writeBytes(high16Offset + (index - 16) * 64,
                                   wideRegs[index * 8], 0, 64);
            }
        } else {
            regs[12416] = readInteger(0, 2);
            regs[12418] = readInteger(2, 2);
            regs[12420] = readInteger(4, 1);
            regs[12424] = readInteger(24, 4);
            for (size_t index = 0; index < 8; ++index)
                readBytes(32 + index * 16, wideRegs[12288 + index * 16], 0, 10);
            for (size_t index = 0; index < 16; ++index)
                readBytes(160 + index * 16, wideRegs[index * 8], 0, 16);
            if (!legacyOnly) {
                const uint64_t saved = readInteger(512, 8) & components;
                const bool savedCompacted = (readInteger(520, 8) >> 63) != 0;
                size_t avxOffset = 576, opmaskOffset = 1088;
                size_t zmmHighOffset = 1152, high16Offset = 1664;
                if (savedCompacted) {
                    opmaskOffset = avxOffset + 256;
                    zmmHighOffset = opmaskOffset + 64;
                    high16Offset = zmmHighOffset + 512;
                }
                if (saved & (1ULL << 2))
                    for (size_t index = 0; index < 16; ++index)
                        readBytes(avxOffset + index * 16,
                                  wideRegs[index * 8], 16, 16);
                if (saved & (1ULL << 5))
                    for (size_t index = 0; index < 8; ++index)
                        regs[8192 + index * 8] =
                            readInteger(opmaskOffset + index * 8, 8);
                if (saved & (1ULL << 6))
                    for (size_t index = 0; index < 16; ++index)
                        readBytes(zmmHighOffset + index * 32,
                                  wideRegs[index * 8], 32, 32);
                if (saved & (1ULL << 7))
                    for (size_t index = 16; index < 32; ++index)
                        readBytes(high16Offset + (index - 16) * 64,
                                  wideRegs[index * 8], 0, 64);
            }
        }
        return std::nullopt;
    }
    case POp::X86_SYSTEM: {
        const auto action = static_cast<X86SystemAction>(op.aux & 0xffU);
        const unsigned selector = (op.aux >> 8) & 0xffU;
        auto raise = [&](X86Fault vector) {
            fault = FaultInfo{vector, 0, insn_.addr};
        };
        auto gpr32 = [&](uint64_t offset) {
            return static_cast<uint32_t>(regValue(offset).value_or(0));
        };
        auto writeGpr32 = [&](uint64_t offset, uint32_t value) {
            regs[offset] = value;
        };
        auto descriptor = [&](DescriptorTable& table, bool load) {
            const auto address = in(op.in0);
            if (!address) return false;
            if (load) {
                uint64_t base = 0;
                uint16_t limit = 0;
                for (unsigned byte = 0; byte < 10; ++byte) {
                    const auto found = ram.find(*address + byte);
                    if (found == ram.end()) return false;
                    if (byte < 2)
                        limit |= static_cast<uint16_t>(found->second) << (byte * 8);
                    else
                        base |= static_cast<uint64_t>(found->second) << ((byte - 2) * 8);
                }
                table.limit = limit;
                table.base = base;
            } else {
                for (unsigned byte = 0; byte < 2; ++byte)
                    ram[*address + byte] = static_cast<uint8_t>(table.limit >> (byte * 8));
                for (unsigned byte = 0; byte < 8; ++byte)
                    ram[*address + 2 + byte] = static_cast<uint8_t>(table.base >> (byte * 8));
            }
            return true;
        };
        auto readMemory = [&](uint64_t address, unsigned bytes,
                              uint64_t& value) {
            value = 0;
            for (unsigned byte = 0; byte < bytes; ++byte) {
                const auto found = ram.find(address + byte);
                if (found == ram.end()) return false;
                value |= static_cast<uint64_t>(found->second) << (byte * 8);
            }
            return true;
        };
        auto writeMemory = [&](uint64_t address, uint64_t value,
                               unsigned bytes) {
            for (unsigned byte = 0; byte < bytes; ++byte)
                ram[address + byte] = static_cast<uint8_t>(value >> (byte * 8));
        };
        auto packedFlags = [&]() {
            uint64_t value = 2;
            const uint64_t offsets[] = {4096, 4097, 4098, 4099, 4100, 4101, 4102};
            const unsigned bits[] = {0, 2, 4, 6, 7, 11, 10};
            for (unsigned index = 0; index < 7; ++index)
                value |= (regValue(offsets[index]).value_or(0) & 1U) << bits[index];
            value |= static_cast<uint64_t>(interruptsEnabled) << 9;
            value |= static_cast<uint64_t>(iopl & 3U) << 12;
            value |= static_cast<uint64_t>(alignmentAccessEnabled) << 18;
            return value;
        };
        auto restoreFlags = [&](uint64_t value) {
            const uint64_t offsets[] = {4096, 4097, 4098, 4099, 4100, 4101, 4102};
            const unsigned bits[] = {0, 2, 4, 6, 7, 11, 10};
            for (unsigned index = 0; index < 7; ++index)
                regs[offsets[index]] = (value >> bits[index]) & 1U;
            if (privilegeLevel <= iopl) interruptsEnabled = ((value >> 9) & 1U) != 0;
            if (privilegeLevel == 0) iopl = static_cast<uint8_t>((value >> 12) & 3U);
            alignmentAccessEnabled = ((value >> 18) & 1U) != 0;
        };
        switch (action) {
        case X86SystemAction::Cpuid: {
            const uint32_t leaf = gpr32(0), subleaf = gpr32(8);
            const uint64_t key = (static_cast<uint64_t>(leaf) << 32) | subleaf;
            const auto found = cpuidLeaves.find(key);
            const std::array<uint32_t, 4> value = found == cpuidLeaves.end()
                ? std::array<uint32_t, 4>{0, 0, 0, 0} : found->second;
            writeGpr32(0, value[0]); writeGpr32(24, value[1]);
            writeGpr32(8, value[2]); writeGpr32(16, value[3]);
            break;
        }
        case X86SystemAction::ReadMsr: {
            const uint32_t index = gpr32(8);
            const auto found = modelSpecificRegs.find(index);
            if (found == modelSpecificRegs.end()) {
                raise(X86Fault::GeneralProtection); break;
            }
            writeGpr32(0, static_cast<uint32_t>(found->second));
            writeGpr32(16, static_cast<uint32_t>(found->second >> 32));
            break;
        }
        case X86SystemAction::WriteMsr: {
            const uint32_t index = gpr32(8);
            if (modelSpecificRegs.find(index) == modelSpecificRegs.end()) {
                raise(X86Fault::GeneralProtection); break;
            }
            const uint64_t value = static_cast<uint64_t>(gpr32(0)) |
                                   (static_cast<uint64_t>(gpr32(16)) << 32);
            const uint64_t upper = value >> 48;
            const bool canonical = upper ==
                ((value & (1ULL << 47)) ? 0xffffULL : 0ULL);
            if ((index == 0xc0000100U || index == 0xc0000101U ||
                 index == 0xc0000102U) && !canonical)
                raise(X86Fault::GeneralProtection);
            else modelSpecificRegs[index] = value;
            break;
        }
        case X86SystemAction::GetXbv:
            if ((controlRegs[4] & (1ULL << 18)) == 0)
                raise(X86Fault::InvalidOpcode);
            else if (gpr32(8) != 0)
                raise(X86Fault::GeneralProtection);
            else {
                writeGpr32(0, static_cast<uint32_t>(xcr0));
                writeGpr32(16, static_cast<uint32_t>(xcr0 >> 32));
            }
            break;
        case X86SystemAction::SetXbv: {
            if ((controlRegs[4] & (1ULL << 18)) == 0) {
                raise(X86Fault::InvalidOpcode); break;
            }
            const uint64_t value = static_cast<uint64_t>(gpr32(0)) |
                                   (static_cast<uint64_t>(gpr32(16)) << 32);
            const bool avx512All = (value & 0xe0U) == 0 ||
                                   (value & 0xe0U) == 0xe0U;
            if (gpr32(8) != 0 || (value & 1U) == 0 ||
                ((value & 4U) && (value & 2U) == 0) || !avx512All ||
                ((value & 0xe0U) && (value & 6U) != 6U) ||
                (value & ~0xe7ULL))
                raise(X86Fault::GeneralProtection);
            else xcr0 = value;
            break;
        }
        case X86SystemAction::ClearTaskSwitched:
            controlRegs[0] &= ~(1ULL << 3); break;
        case X86SystemAction::SwapGs:
            std::swap(modelSpecificRegs[0xc0000101U],
                      modelSpecificRegs[0xc0000102U]);
            break;
        case X86SystemAction::DisableInterrupts:
            interruptsEnabled = false; interruptShadow = false; break;
        case X86SystemAction::EnableInterrupts:
            interruptsEnabled = true; interruptShadow = true; break;
        case X86SystemAction::Halt:
            halted = true; break;
        case X86SystemAction::InvalidatePage: {
            const auto address = in(op.in0);
            if (address) invalidatedPages.push_back(*address & ~0xfffULL);
            break;
        }
        case X86SystemAction::InvalidateCaches:
        case X86SystemAction::WriteBackInvalidateCaches:
            ++cacheGeneration; break;
        case X86SystemAction::ReadControl: {
            const auto found = controlRegs.find(selector);
            if (found == controlRegs.end() || !op.out)
                raise(X86Fault::GeneralProtection);
            else return found->second;
            break;
        }
        case X86SystemAction::WriteControl: {
            const auto value = in(op.in0);
            if (!value || (selector != 0 && selector != 2 && selector != 3 &&
                           selector != 4 && selector != 8))
                raise(X86Fault::GeneralProtection);
            else if (selector == 0 &&
                     (((*value & (1ULL << 31)) && (*value & 1U) == 0) ||
                      ((*value & (1ULL << 29)) &&
                       (*value & (1ULL << 30)) == 0) ||
                      (*value & ~0xe005003fULL)))
                raise(X86Fault::GeneralProtection);
            else if (selector == 8 && (*value & ~0x0fULL))
                raise(X86Fault::GeneralProtection);
            else controlRegs[selector] = *value;
            break;
        }
        case X86SystemAction::StoreGdtr:
            if (privilegeLevel != 0 && (controlRegs[4] & (1ULL << 11)))
                raise(X86Fault::GeneralProtection);
            else descriptor(gdtr, false);
            break;
        case X86SystemAction::StoreIdtr:
            if (privilegeLevel != 0 && (controlRegs[4] & (1ULL << 11)))
                raise(X86Fault::GeneralProtection);
            else descriptor(idtr, false);
            break;
        case X86SystemAction::LoadGdtr: descriptor(gdtr, true); break;
        case X86SystemAction::LoadIdtr: descriptor(idtr, true); break;
        case X86SystemAction::StoreLdt:
        case X86SystemAction::StoreTask:
        case X86SystemAction::LoadLdt:
        case X86SystemAction::LoadTask: {
            const bool load = action == X86SystemAction::LoadLdt ||
                              action == X86SystemAction::LoadTask;
            const auto value = in(op.in0);
            if (load) {
                if (!value) raise(X86Fault::GeneralProtection);
                else if (action == X86SystemAction::LoadLdt)
                    ldtr = static_cast<uint16_t>(*value);
                else taskRegister = static_cast<uint16_t>(*value);
            } else {
                return action == X86SystemAction::StoreLdt ? ldtr : taskRegister;
            }
            break;
        }
        case X86SystemAction::PortIn: {
            const auto port = in(op.in0);
            if (!port) break;
            const unsigned width = std::max<unsigned>(1, selector);
            const uint64_t mask = width >= 4 ? 0xffffffffULL
                                             : ((1ULL << (width * 8)) - 1);
            return static_cast<uint64_t>(
                       ioPorts[static_cast<uint16_t>(*port)]) & mask;
        }
        case X86SystemAction::PortOut: {
            const auto port = in(op.in0), value = in(op.in1);
            if (!port || !value) break;
            const unsigned width = std::max<unsigned>(1, selector);
            const uint64_t mask = width >= 4 ? 0xffffffffULL
                                             : ((1ULL << (width * 8)) - 1);
            ioPorts[static_cast<uint16_t>(*port)] =
                static_cast<uint32_t>(*value & mask);
            break;
        }
        case X86SystemAction::SignExtendHigh: {
            const unsigned width = selector;
            const uint64_t low = regValue(0).value_or(0);
            if (width == 2)
                regs[16] = (regValue(16).value_or(0) & ~0xffffULL) |
                           ((low & 0x8000U) ? 0xffffU : 0U);
            else if (width == 4)
                regs[16] = (low & 0x80000000U) ? 0xffffffffU : 0U;
            else if (width == 8)
                regs[16] = (low >> 63) ? ~0ULL : 0ULL;
            break;
        }
        case X86SystemAction::MultiplyAccumulator: {
            const auto source = in(op.in0);
            const unsigned width = selector & 0x0fU;
            const bool signedMultiply = (selector & 0x80U) != 0;
            if (!source || (width != 1 && width != 2 && width != 4 && width != 8)) break;
            const unsigned bits = width * 8;
            const uint64_t mask = width == 8 ? ~0ULL : ((1ULL << bits) - 1);
            const uint64_t left = regValue(0).value_or(0) & mask;
            uint64_t low = 0, high = 0;
            bool overflow = false;
            const uint64_t right = *source & mask;
            if (width == 8) {
                const uint64_t leftLow = static_cast<uint32_t>(left);
                const uint64_t leftHigh = left >> 32;
                const uint64_t rightLow = static_cast<uint32_t>(right);
                const uint64_t rightHigh = right >> 32;
                uint64_t product = leftLow * rightLow;
                const uint64_t bottom = static_cast<uint32_t>(product);
                product = leftHigh * rightLow + (product >> 32);
                const uint64_t middle = static_cast<uint32_t>(product);
                const uint64_t carry = product >> 32;
                product = leftLow * rightHigh + middle;
                low = (product << 32) | bottom;
                high = leftHigh * rightHigh + carry + (product >> 32);
                if (signedMultiply) {
                    if (left >> 63) high -= right;
                    if (right >> 63) high -= left;
                    overflow = high != ((low >> 63) ? ~0ULL : 0ULL);
                } else {
                    overflow = high != 0;
                }
            } else {
                if (signedMultiply) {
                    const uint64_t sign = 1ULL << (bits - 1);
                    const int64_t signedLeft = static_cast<int64_t>((left ^ sign) - sign);
                    const int64_t signedRight = static_cast<int64_t>((right ^ sign) - sign);
                    const int64_t product = signedLeft * signedRight;
                    low = static_cast<uint64_t>(product) & mask;
                    high = static_cast<uint64_t>(product >> bits) & mask;
                    const int64_t truncated = static_cast<int64_t>((low ^ sign) - sign);
                    overflow = product != truncated;
                } else {
                    const uint64_t product = left * right;
                    low = product & mask;
                    high = (product >> bits) & mask;
                    overflow = high != 0;
                }
            }
            if (width == 1) {
                regs[0] = (regValue(0).value_or(0) & ~0xffffULL) |
                          low | (high << 8);
            } else {
                regs[0] = width == 4 ? static_cast<uint32_t>(low)
                                     : ((regValue(0).value_or(0) & ~mask) | low);
                regs[16] = width == 4 ? static_cast<uint32_t>(high)
                                      : ((regValue(16).value_or(0) & ~mask) | high);
            }
            regs[4096] = overflow; regs[4101] = overflow;
            break;
        }
        case X86SystemAction::CompareExchangeWide: {
            const auto address = in(op.in0);
            const unsigned width = selector;
            if (!address || (width != 8 && width != 16)) break;
            uint64_t memoryLow = 0, memoryHigh = 0;
            if (!readMemory(*address, 8, memoryLow) ||
                (width == 16 && !readMemory(*address + 8, 8, memoryHigh))) break;
            const uint64_t compareLow = regValue(0).value_or(0);
            const uint64_t compareHigh = width == 8
                ? static_cast<uint32_t>(regValue(16).value_or(0))
                : regValue(16).value_or(0);
            const bool equal = width == 8
                ? static_cast<uint32_t>(memoryLow) == static_cast<uint32_t>(compareLow) &&
                  static_cast<uint32_t>(memoryLow >> 32) == static_cast<uint32_t>(compareHigh)
                : memoryLow == compareLow && memoryHigh == compareHigh;
            regs[4099] = equal;
            if (equal) {
                if (width == 8) {
                    const uint64_t replacement =
                        static_cast<uint32_t>(regValue(24).value_or(0)) |
                        (static_cast<uint64_t>(static_cast<uint32_t>(regValue(8).value_or(0))) << 32);
                    writeMemory(*address, replacement, 8);
                } else {
                    writeMemory(*address, regValue(24).value_or(0), 8);
                    writeMemory(*address + 8, regValue(8).value_or(0), 8);
                }
            } else if (width == 8) {
                regs[0] = static_cast<uint32_t>(memoryLow);
                regs[16] = static_cast<uint32_t>(memoryLow >> 32);
            } else {
                regs[0] = memoryLow; regs[16] = memoryHigh;
            }
            break;
        }
        case X86SystemAction::EnterFrame: {
            const auto allocation = in(op.in0), nestingValue = in(op.in1);
            if (!allocation || !nestingValue) break;
            uint64_t sp = regValue(32).value_or(0), bp = regValue(40).value_or(0);
            sp -= 8; writeMemory(sp, bp, 8);
            const uint64_t frame = sp;
            const unsigned nesting = static_cast<unsigned>(*nestingValue & 31U);
            for (unsigned level = 1; level < nesting; ++level) {
                bp -= 8; uint64_t parent = 0; readMemory(bp, 8, parent);
                sp -= 8; writeMemory(sp, parent, 8);
            }
            if (nesting) { sp -= 8; writeMemory(sp, frame, 8); }
            regs[40] = frame; regs[32] = sp - (*allocation & 0xffffU);
            break;
        }
        case X86SystemAction::PopValue: {
            uint64_t value = 0, sp = regValue(32).value_or(0);
            if (!readMemory(sp, selector, value)) break;
            regs[32] = sp + selector;
            if (op.out) return value;
            break;
        }
        case X86SystemAction::PushFlags: {
            uint64_t sp = regValue(32).value_or(0) - selector;
            writeMemory(sp, packedFlags(), selector); regs[32] = sp; break;
        }
        case X86SystemAction::PopFlags: {
            uint64_t value = 0, sp = regValue(32).value_or(0);
            if (readMemory(sp, selector, value)) {
                restoreFlags(value); regs[32] = sp + selector;
            }
            break;
        }
        case X86SystemAction::LoadAhFlags: {
            const uint64_t flags = packedFlags();
            const uint8_t ah = static_cast<uint8_t>(flags & 0xd5U);
            regs[0] = (regValue(0).value_or(0) & ~0xff00ULL) |
                      (static_cast<uint64_t>(ah) << 8); break;
        }
        case X86SystemAction::StoreAhFlags: {
            const uint8_t ah = static_cast<uint8_t>(regValue(0).value_or(0) >> 8);
            regs[4096] = ah & 1U; regs[4097] = (ah >> 2) & 1U;
            regs[4098] = (ah >> 4) & 1U; regs[4099] = (ah >> 6) & 1U;
            regs[4100] = (ah >> 7) & 1U; break;
        }
        case X86SystemAction::SetAlCarry:
            regs[0] = (regValue(0).value_or(0) & ~0xffULL) |
                      (regValue(4096).value_or(0) ? 0xffU : 0U); break;
        case X86SystemAction::LoadMxcsr: {
            const auto address = in(op.in0); uint64_t value = 0;
            if (address && readMemory(*address, 4, value)) {
                if (value & 0xffff0000U) raise(X86Fault::GeneralProtection);
                else mxcsr = static_cast<uint32_t>(value);
            }
            break;
        }
        case X86SystemAction::StoreMxcsr: {
            const auto address = in(op.in0);
            if (address) writeMemory(*address, mxcsr, 4);
            break;
        }
        case X86SystemAction::StringPortIn:
        case X86SystemAction::StringPortOut: {
            const unsigned width = selector;
            uint64_t count = 1, pointerOffset =
                action == X86SystemAction::StringPortIn ? 56 : 48;
            uint64_t pointer = regValue(pointerOffset).value_or(0);
            const uint16_t port = static_cast<uint16_t>(regValue(16).value_or(0));
            const int64_t step = regValue(4102).value_or(0) ?
                -static_cast<int64_t>(width) : static_cast<int64_t>(width);
            while (count--) {
                if (action == X86SystemAction::StringPortIn)
                    writeMemory(pointer, ioPorts[port], width);
                else { uint64_t value = 0; if (readMemory(pointer, width, value))
                    ioPorts[port] = static_cast<uint32_t>(value); }
                pointer = static_cast<uint64_t>(static_cast<int64_t>(pointer) + step);
            }
            regs[pointerOffset] = pointer; break;
        }
        case X86SystemAction::ReadTimestamp:
        case X86SystemAction::ReadTimestampAux:
            writeGpr32(0, static_cast<uint32_t>(timestampCounter));
            writeGpr32(16, static_cast<uint32_t>(timestampCounter >> 32));
            if (action == X86SystemAction::ReadTimestampAux) writeGpr32(8, processorId);
            ++timestampCounter; break;
        case X86SystemAction::ReadPerformanceCounter: {
            const uint32_t index = gpr32(8); const uint64_t value = performanceCounters[index];
            writeGpr32(0, static_cast<uint32_t>(value));
            writeGpr32(16, static_cast<uint32_t>(value >> 32)); break;
        }
        case X86SystemAction::RandomValue: {
            randomState ^= randomState >> 12; randomState ^= randomState << 25;
            randomState ^= randomState >> 27; const uint64_t value = randomState * 0x2545f4914f6cdd1dULL;
            regs[4096] = 1; if (op.out) return value; break;
        }
        case X86SystemAction::ReadProcessorId:
            if (op.out) return processorId;
            break;
        case X86SystemAction::ReadShadowStack:
            if (op.out) return shadowStackPointer;
            break;
        case X86SystemAction::ArmMonitor:
            monitoredAddress = regValue(0).value_or(0); monitorArmed = true; break;
        case X86SystemAction::MonitorWait:
            halted = monitorArmed; monitorArmed = false; break;
        case X86SystemAction::SetAccessControl:
            if (privilegeLevel != 0) raise(X86Fault::InvalidOpcode);
            else alignmentAccessEnabled = selector != 0;
            break;
        case X86SystemAction::FastSystemCall: {
            regs[8] = insn_.nextAddr; regs[88] = packedFlags();
            instructionPointer = modelSpecificRegs[0xc0000082U];
            restoreFlags(packedFlags() & ~modelSpecificRegs[0xc0000084U]);
            privilegeLevel = 0; codeSegment = static_cast<uint16_t>(modelSpecificRegs[0xc0000081U] >> 32);
            lastBranch_ = instructionPointer; break;
        }
        case X86SystemAction::FastSystemReturn:
            if (privilegeLevel != 0) raise(X86Fault::GeneralProtection);
            else { instructionPointer = regValue(8).value_or(0); restoreFlags(regValue(88).value_or(2));
                privilegeLevel = 3; lastBranch_ = instructionPointer; } break;
        case X86SystemAction::SoftwareInterrupt: {
            const auto vector = in(op.in0);
            fault = FaultInfo{static_cast<X86Fault>(vector.value_or(0) & 0xffU), 0, insn_.addr}; break;
        }
        case X86SystemAction::InterruptReturn:
        case X86SystemAction::FarReturn: {
            uint64_t sp = regValue(32).value_or(0), target = 0, cs = 0, flags = 0;
            if (!readMemory(sp, 8, target) || !readMemory(sp + 8, 8, cs)) break;
            sp += 16; codeSegment = static_cast<uint16_t>(cs); instructionPointer = target;
            if (action == X86SystemAction::InterruptReturn && readMemory(sp, 8, flags)) {
                restoreFlags(flags); sp += 8;
            }
            sp += selector; regs[32] = sp; lastBranch_ = target; break;
        }
        case X86SystemAction::AccessRights:
        case X86SystemAction::SegmentLimit: {
            const auto selectorValue = in(op.in0); if (!selectorValue) break;
            const uint16_t sel = static_cast<uint16_t>(*selectorValue);
            const bool valid = (sel & ~3U) != 0 && (sel & 4U) == 0;
            regs[4099] = valid;
            if (valid && op.out) {
                uint64_t descriptorValue = 0;
                if (!readMemory(gdtr.base + (sel & ~7U), 8, descriptorValue)) break;
                if (action == X86SystemAction::AccessRights)
                    return (descriptorValue >> 32) & 0x00f0ff00U;
                const uint64_t limit = (descriptorValue & 0xffffU) |
                                       ((descriptorValue >> 32) & 0x000f0000U);
                return ((descriptorValue >> 55) & 1U) ? ((limit << 12) | 0xfffU) : limit;
            }
            break;
        }
        case X86SystemAction::TranslateByte: {
            const uint64_t address = regValue(24).value_or(0) +
                                     (regValue(0).value_or(0) & 0xffU);
            uint64_t value = 0;
            if (readMemory(address, 1, value))
                regs[0] = (regValue(0).value_or(0) & ~0xffULL) | value;
            break;
        }
        case X86SystemAction::None: break;
        }
        return std::nullopt;
    }
    case POp::X86_DIVIDE: {
        const auto divisorValue = in(op.in0);
        const unsigned width = op.aux & 0x0fU;
        if (!divisorValue || (width != 1 && width != 2 &&
                              width != 4 && width != 8))
            return std::nullopt;
        constexpr uint64_t rax = 0, rdx = 16;
        const uint64_t oldRax = regValue(rax).value_or(0);
        const uint64_t oldRdx = regValue(rdx).value_or(0);
        auto divideError = [&]() {
            fault = FaultInfo{X86Fault::DivideError, 0, insn_.addr};
        };
        if (op.aux & 0x0100U) {
            const uint64_t divisor = *divisorValue &
                (width == 8 ? ~0ULL : ((1ULL << (width * 8)) - 1));
            if (divisor == 0) { divideError(); return std::nullopt; }
            if (width == 1) {
                const uint64_t dividend = oldRax & 0xffffU;
                const uint64_t quotient = dividend / divisor;
                if (quotient > 0xffU) { divideError(); return std::nullopt; }
                regs[rax] = (oldRax & ~0xffffULL) | quotient |
                            ((dividend % divisor) << 8);
                return std::nullopt;
            }
            if (width == 2) {
                const uint64_t dividend = ((oldRdx & 0xffffU) << 16) |
                                          (oldRax & 0xffffU);
                const uint64_t quotient = dividend / divisor;
                if (quotient > 0xffffU) { divideError(); return std::nullopt; }
                regs[rax] = (oldRax & ~0xffffULL) | quotient;
                regs[rdx] = (oldRdx & ~0xffffULL) | (dividend % divisor);
                return std::nullopt;
            }
            if (width == 4) {
                const uint64_t dividend =
                    (static_cast<uint64_t>(static_cast<uint32_t>(oldRdx)) << 32) |
                    static_cast<uint32_t>(oldRax);
                const uint64_t quotient = dividend / divisor;
                if (quotient > 0xffffffffULL) {
                    divideError(); return std::nullopt;
                }
                regs[rax] = static_cast<uint32_t>(quotient);
                regs[rdx] = static_cast<uint32_t>(dividend % divisor);
                return std::nullopt;
            }
            uint64_t quotient = 0, remainder = 0;
            bool quotientHigh = false;
            for (int bit = 127; bit >= 0; --bit) {
                const uint64_t incoming = bit >= 64
                    ? ((oldRdx >> (bit - 64)) & 1U)
                    : ((oldRax >> bit) & 1U);
                const bool carry = (remainder >> 63) != 0;
                remainder = (remainder << 1) | incoming;
                if (carry || remainder >= divisor) {
                    remainder -= divisor;
                    if (bit >= 64) quotientHigh = true;
                    else quotient |= 1ULL << bit;
                }
            }
            if (quotientHigh) { divideError(); return std::nullopt; }
            regs[rax] = quotient;
            regs[rdx] = remainder;
            return std::nullopt;
        }
        if (width == 1) {
            const int divisor = static_cast<int8_t>(*divisorValue);
            const int dividend = static_cast<int16_t>(oldRax & 0xffffU);
            if (divisor == 0) { divideError(); return std::nullopt; }
            const int quotient = dividend / divisor;
            if (quotient < -128 || quotient > 127) {
                divideError(); return std::nullopt;
            }
            const int remainder = dividend % divisor;
            regs[rax] = (oldRax & ~0xffffULL) |
                        static_cast<uint8_t>(quotient) |
                        (static_cast<uint64_t>(static_cast<uint8_t>(remainder)) << 8);
            return std::nullopt;
        }
        if (width == 2) {
            const int32_t dividend = static_cast<int32_t>(
                ((oldRdx & 0xffffU) << 16) | (oldRax & 0xffffU));
            const int32_t divisor = static_cast<int16_t>(*divisorValue);
            if (divisor == 0 ||
                (dividend == std::numeric_limits<int32_t>::min() && divisor == -1)) {
                divideError(); return std::nullopt;
            }
            const int32_t quotient = dividend / divisor;
            if (quotient < -32768 || quotient > 32767) {
                divideError(); return std::nullopt;
            }
            const int32_t remainder = dividend % divisor;
            regs[rax] = (oldRax & ~0xffffULL) |
                        static_cast<uint16_t>(quotient);
            regs[rdx] = (oldRdx & ~0xffffULL) |
                        static_cast<uint16_t>(remainder);
            return std::nullopt;
        }
        if (width == 4) {
            const int64_t dividend = static_cast<int64_t>(
                (static_cast<uint64_t>(static_cast<uint32_t>(oldRdx)) << 32) |
                static_cast<uint32_t>(oldRax));
            const int64_t divisor = static_cast<int32_t>(*divisorValue);
            if (divisor == 0 ||
                (dividend == std::numeric_limits<int64_t>::min() && divisor == -1)) {
                divideError(); return std::nullopt;
            }
            const int64_t quotient = dividend / divisor;
            if (quotient < std::numeric_limits<int32_t>::min() ||
                quotient > std::numeric_limits<int32_t>::max()) {
                divideError(); return std::nullopt;
            }
            const int64_t remainder = dividend % divisor;
            regs[rax] = static_cast<uint32_t>(quotient);
            regs[rdx] = static_cast<uint32_t>(remainder);
            return std::nullopt;
        }

        const int64_t signedDivisor = static_cast<int64_t>(*divisorValue);
        if (signedDivisor == 0) { divideError(); return std::nullopt; }
        const bool dividendNegative = (oldRdx >> 63) != 0;
        const bool divisorNegative = signedDivisor < 0;
        uint64_t magnitudeLow = oldRax, magnitudeHigh = oldRdx;
        if (dividendNegative) {
            magnitudeLow = ~magnitudeLow + 1;
            magnitudeHigh = ~magnitudeHigh + (magnitudeLow == 0 ? 1 : 0);
        }
        const uint64_t divisorMagnitude = divisorNegative
            ? (~static_cast<uint64_t>(signedDivisor) + 1)
            : static_cast<uint64_t>(signedDivisor);
        uint64_t quotientMagnitude = 0, remainderMagnitude = 0;
        bool quotientHigh = false;
        for (int bit = 127; bit >= 0; --bit) {
            const uint64_t incoming = bit >= 64
                ? ((magnitudeHigh >> (bit - 64)) & 1U)
                : ((magnitudeLow >> bit) & 1U);
            const bool carry = (remainderMagnitude >> 63) != 0;
            remainderMagnitude = (remainderMagnitude << 1) | incoming;
            if (carry || remainderMagnitude >= divisorMagnitude) {
                remainderMagnitude -= divisorMagnitude;
                if (bit >= 64) quotientHigh = true;
                else quotientMagnitude |= 1ULL << bit;
            }
        }
        const bool quotientNegative = dividendNegative != divisorNegative;
        const uint64_t limit = quotientNegative ? (1ULL << 63)
                                                : ((1ULL << 63) - 1);
        if (quotientHigh || quotientMagnitude > limit) {
            divideError(); return std::nullopt;
        }
        regs[rax] = quotientNegative ? (~quotientMagnitude + 1)
                                     : quotientMagnitude;
        regs[rdx] = dividendNegative ? (~remainderMagnitude + 1)
                                     : remainderMagnitude;
        return std::nullopt;
    }
    case POp::X86_STRING: {
        // aux: low nibble MOVS/CMPS/STOS/LODS/SCAS, next nibble element
        // width, then repetition mode none/REP/REPE/REPNE.
        const unsigned operation = op.aux & 0x0fU;
        const unsigned width = (op.aux >> 4) & 0x0fU;
        const unsigned repeat = (op.aux >> 8) & 0x03U;
        if ((width != 1 && width != 2 && width != 4 && width != 8) ||
            operation < 1 || operation > 5)
            return std::nullopt;
        constexpr uint64_t rax = 0, rcx = 8, rsi = 48, rdi = 56;
        constexpr uint64_t cf = 4096, pf = 4097, af = 4098;
        constexpr uint64_t zf = 4099, sf = 4100, of = 4101, df = 4102;
        uint64_t source = regValue(rsi).value_or(0);
        uint64_t destination = regValue(rdi).value_or(0);
        uint64_t count = repeat ? regValue(rcx).value_or(0) : 1;
        const int64_t step = regValue(df).value_or(0)
                                 ? -static_cast<int64_t>(width)
                                 : static_cast<int64_t>(width);
        const uint64_t mask = width == 8 ? ~0ULL
                                         : ((1ULL << (width * 8)) - 1);
        auto readMemory = [&](uint64_t address, uint64_t& value) {
            value = 0;
            for (unsigned byte = 0; byte < width; ++byte) {
                const auto found = ram.find(address + byte);
                if (found == ram.end()) return false;
                value |= static_cast<uint64_t>(found->second) << (byte * 8);
            }
            return true;
        };
        auto writeMemory = [&](uint64_t address, uint64_t value) {
            for (unsigned byte = 0; byte < width; ++byte)
                ram[address + byte] = static_cast<uint8_t>(value >> (byte * 8));
        };
        auto compare = [&](uint64_t lhs, uint64_t rhs) {
            lhs &= mask; rhs &= mask;
            const uint64_t result = (lhs - rhs) & mask;
            regs[cf] = lhs < rhs;
            uint8_t parity = static_cast<uint8_t>(result);
            parity ^= parity >> 4; parity ^= parity >> 2; parity ^= parity >> 1;
            regs[pf] = (~parity) & 1U;
            regs[af] = ((lhs ^ rhs ^ result) >> 4) & 1U;
            regs[zf] = result == 0;
            regs[sf] = (result >> (width * 8 - 1)) & 1U;
            regs[of] = (((lhs ^ rhs) & (lhs ^ result)) >>
                        (width * 8 - 1)) & 1U;
        };
        while (count != 0) {
            uint64_t left = 0, right = 0;
            bool completed = true;
            switch (operation) {
            case 1:
                completed = readMemory(source, left);
                if (completed) writeMemory(destination, left);
                break;
            case 2:
                completed = readMemory(source, left) &&
                            readMemory(destination, right);
                if (completed) compare(left, right);
                break;
            case 3:
                writeMemory(destination, regValue(rax).value_or(0));
                break;
            case 4:
                completed = readMemory(source, left);
                if (completed) {
                    const uint64_t old = regValue(rax).value_or(0);
                    regs[rax] = width == 8 ? left
                                : width == 4 ? static_cast<uint32_t>(left)
                                : (old & ~mask) | (left & mask);
                }
                break;
            case 5:
                completed = readMemory(destination, right);
                if (completed) compare(regValue(rax).value_or(0), right);
                break;
            default: completed = false; break;
            }
            if (!completed) break;
            if (operation == 1 || operation == 2 || operation == 4)
                source = static_cast<uint64_t>(source + step);
            if (operation == 1 || operation == 2 || operation == 3 ||
                operation == 5)
                destination = static_cast<uint64_t>(destination + step);
            if (repeat) {
                --count;
                regs[rcx] = count;
            } else {
                count = 0;
            }
            if ((operation == 2 || operation == 5) && repeat == 2 &&
                regs[zf] == 0)
                break;
            if ((operation == 2 || operation == 5) && repeat == 3 &&
                regs[zf] != 0)
                break;
        }
        if (operation == 1 || operation == 2 || operation == 4)
            regs[rsi] = source;
        if (operation == 1 || operation == 2 || operation == 3 ||
            operation == 5)
            regs[rdi] = destination;
        return std::nullopt;
    }
    case POp::X86_GUARD: {
        // aux low nibble is the architectural gate.  Feature gates use
        // bit 8+ as an index into x86Features.
        const uint16_t gate = op.aux & 0x0fU;
        const uint16_t feature = (op.aux >> 8) & 0x3fU;
        auto raise = [&](X86Fault vector) {
            fault = FaultInfo{vector, 0, insn_.addr};
        };
        if (feature && (x86Features & (1ULL << (feature - 1))) == 0) {
            raise(X86Fault::InvalidOpcode);
            return std::nullopt;
        }
        const uint64_t cr0 = controlRegs.count(0) ? controlRegs[0] : 0;
        const uint64_t cr4 = controlRegs.count(4) ? controlRegs[4] : ~0ULL;
        if (gate == 1 && privilegeLevel != 0)
            raise(X86Fault::GeneralProtection);
        else if (gate == 7 && privilegeLevel > iopl)
            raise(X86Fault::GeneralProtection);
        else if ((gate == 2 || gate == 5) &&
                 (cr0 & ((1ULL << 2) | (1ULL << 3))))
            raise(X86Fault::DeviceNotAvailable);
        else if ((gate == 3 || gate == 4) && (cr0 & (1ULL << 2)))
            raise(X86Fault::InvalidOpcode); // CR0.EM disables SSE/AVX
        else if ((gate == 3 || gate == 4) && (cr0 & (1ULL << 3)))
            raise(X86Fault::DeviceNotAvailable); // CR0.TS
        else if (gate == 6 && (cr0 & (1ULL << 1)) &&
                              (cr0 & (1ULL << 3)))
            raise(X86Fault::DeviceNotAvailable); // CR0.MP && CR0.TS
        else if (gate == 3 && (cr4 & (1ULL << 9)) == 0)
            raise(X86Fault::InvalidOpcode); // CR4.OSFXSR
        else if (gate == 4 && ((cr4 & (1ULL << 18)) == 0 ||
                               (xcr0 & 0x6) != 0x6))
            raise(X86Fault::InvalidOpcode); // OSXSAVE + XMM/YMM state
        else if (gate == 2 || gate == 6) {
            const uint64_t control = regValue(12416).value_or(0x037f);
            const uint64_t status = regValue(12418).value_or(0);
            if ((status & (~control) & 0x3fU) != 0)
                raise(X86Fault::X87FloatingPoint);
        }
        return std::nullopt;
    }
    case POp::X87_REQUIRE:
    case POp::X87_PUSH:
    case POp::X87_POP:
    case POp::X87_FREE:
    case POp::X87_TAG:
    case POp::X87_EXAMINE:
    case POp::X87_ROTATE:
    case POp::X87_COMPARE_CHECK: {
        constexpr uint64_t stBase = 12288;
        constexpr uint64_t controlOffset = 12416;
        constexpr uint64_t statusOffset = 12418;
        constexpr uint64_t tagOffset = 12420;
        const uint16_t control = static_cast<uint16_t>(
            regValue(controlOffset).value_or(0x037f));
        uint16_t status = static_cast<uint16_t>(
            regValue(statusOffset).value_or(0));
        const auto knownTags = regValue(tagOffset);
        uint16_t tags = static_cast<uint16_t>(knownTags.value_or(0xffff));
        auto setTop = [&](unsigned top) {
            status = static_cast<uint16_t>((status & ~(7U << 11)) |
                                           ((top & 7U) << 11));
        };
        auto tagAt = [&](unsigned index) {
            return static_cast<unsigned>((tags >> ((index & 7U) * 2)) & 3U);
        };
        auto setTag = [&](unsigned index, unsigned tag) {
            const unsigned shift = (index & 7U) * 2;
            tags = static_cast<uint16_t>((tags & ~(3U << shift)) |
                                         ((tag & 3U) << shift));
        };
        auto indefinite = [] {
            std::vector<uint8_t> value(10, 0);
            const uint64_t significand = 0xc000000000000000ULL;
            const uint16_t signExponent = 0xffffU;
            std::memcpy(value.data(), &significand, 8);
            std::memcpy(value.data() + 8, &signExponent, 2);
            return value;
        };
        auto classify = [](const std::vector<uint8_t>& value) {
            if (value.size() < 10) return 2U;
            uint64_t significand = 0;
            uint16_t signExponent = 0;
            std::memcpy(&significand, value.data(), 8);
            std::memcpy(&signExponent, value.data() + 8, 2);
            const unsigned exponent = signExponent & 0x7fffU;
            if (exponent == 0 && significand == 0) return 1U;
            if (exponent == 0 || exponent == 0x7fffU ||
                (significand & (1ULL << 63)) == 0)
                return 2U;
            return 0U;
        };
        if (!knownTags) {
            for (unsigned slot = 0; slot < 8; ++slot) {
                const auto found = wideRegs.find(stBase + slot * 16);
                if (found != wideRegs.end() && found->second.size() >= 10)
                    setTag(slot, classify(found->second));
            }
        }
        auto stackFault = [&](bool overflow) {
            status |= (1U << 0) | (1U << 6); // IE | SF
            if (overflow) status |= 1U << 9;
            else status &= static_cast<uint16_t>(~(1U << 9));
            if ((control & 1U) == 0) {
                status |= (1U << 7) | (1U << 15); // ES | B
                suppressRemaining_ = true;
                return false;
            }
            return true;
        };
        const unsigned index = op.aux & 7U;
        if (op.op == POp::X87_COMPARE_CHECK) {
            auto invalidEncoding = [](const std::vector<uint8_t>& value,
                                      bool& nan, bool& signaling) {
                nan = signaling = false;
                if (value.size() < 10) return true;
                uint64_t significand = 0;
                uint16_t signExponent = 0;
                std::memcpy(&significand, value.data(), 8);
                std::memcpy(&signExponent, value.data() + 8, 2);
                const unsigned exponent = signExponent & 0x7fffU;
                if (exponent == 0x7fffU &&
                    significand != 0x8000000000000000ULL) {
                    nan = true;
                    signaling = (significand & (1ULL << 62)) == 0;
                    return false;
                }
                return exponent != 0 &&
                       (significand & (1ULL << 63)) == 0;
            };
            const auto lhs = wideValue(op.in0), rhs = wideValue(op.in1);
            bool lhsNan = false, lhsSignaling = false;
            bool rhsNan = false, rhsSignaling = false;
            const bool unsupported = !lhs || !rhs ||
                invalidEncoding(lhs.value_or(std::vector<uint8_t>{}),
                                lhsNan, lhsSignaling) ||
                invalidEncoding(rhs.value_or(std::vector<uint8_t>{}),
                                rhsNan, rhsSignaling);
            const bool quietCompare = (op.aux & 0x0100U) != 0;
            if (unsupported || lhsSignaling || rhsSignaling ||
                (!quietCompare && (lhsNan || rhsNan))) {
                status |= 1U << 0;
                if ((control & 1U) == 0) {
                    status |= (1U << 7) | (1U << 15);
                    suppressRemaining_ = true;
                }
            }
        } else if (op.op == POp::X87_REQUIRE) {
            if (tagAt(index) == 3 && stackFault(false)) {
                wideRegs[stBase + index * 16] = indefinite();
                setTag(index, 2);
            }
        } else if (op.op == POp::X87_PUSH) {
            auto value = wideValue(op.in0);
            const bool overflow = tagAt(7) != 3;
            if (overflow && !stackFault(true)) {
                regs[statusOffset] = status;
                return std::nullopt;
            }
            for (unsigned slot = 7; slot > 0; --slot)
                wideRegs[stBase + slot * 16] =
                    wideRegs[stBase + (slot - 1) * 16];
            std::vector<uint8_t> pushed = overflow || !value
                                              ? indefinite() : *value;
            pushed.resize(10, 0);
            wideRegs[stBase] = pushed;
            tags = static_cast<uint16_t>((tags << 2) |
                                         (overflow ? 2U : classify(pushed)));
            setTop(((status >> 11) - 1U) & 7U);
        } else if (op.op == POp::X87_POP) {
            if (tagAt(0) == 3 && !stackFault(false)) {
                regs[statusOffset] = status;
                return std::nullopt;
            }
            for (unsigned slot = 0; slot < 7; ++slot)
                wideRegs[stBase + slot * 16] =
                    wideRegs[stBase + (slot + 1) * 16];
            wideRegs[stBase + 7 * 16].assign(10, 0);
            tags = static_cast<uint16_t>((tags >> 2) | 0xc000U);
            setTop(((status >> 11) + 1U) & 7U);
        } else if (op.op == POp::X87_FREE) {
            setTag(index, 3);
        } else if (op.op == POp::X87_TAG) {
            auto value = wideValue(op.in0);
            if (value) setTag(index, classify(*value));
        } else if (op.op == POp::X87_ROTATE) {
            if ((op.aux & 1U) == 0) { // FDECSTP
                const auto saved = wideRegs[stBase + 7 * 16];
                for (unsigned slot = 7; slot > 0; --slot)
                    wideRegs[stBase + slot * 16] =
                        wideRegs[stBase + (slot - 1) * 16];
                wideRegs[stBase] = saved;
                tags = static_cast<uint16_t>((tags << 2) | (tags >> 14));
                setTop(((status >> 11) - 1U) & 7U);
            } else { // FINCSTP
                const auto saved = wideRegs[stBase];
                for (unsigned slot = 0; slot < 7; ++slot)
                    wideRegs[stBase + slot * 16] =
                        wideRegs[stBase + (slot + 1) * 16];
                wideRegs[stBase + 7 * 16] = saved;
                tags = static_cast<uint16_t>((tags >> 2) | (tags << 14));
                setTop(((status >> 11) + 1U) & 7U);
            }
        } else {
            const unsigned tag = tagAt(0);
            unsigned c3c2c0 = 0;
            bool sign = false;
            const auto found = wideRegs.find(stBase);
            if (tag == 3 || found == wideRegs.end() || found->second.size() < 10) {
                c3c2c0 = 5; // empty: 101
            } else {
                uint64_t significand = 0;
                uint16_t signExponent = 0;
                std::memcpy(&significand, found->second.data(), 8);
                std::memcpy(&signExponent, found->second.data() + 8, 2);
                sign = (signExponent & 0x8000U) != 0;
                const unsigned exponent = signExponent & 0x7fffU;
                if (exponent == 0 && significand == 0) c3c2c0 = 4; // zero
                else if (exponent == 0) c3c2c0 = 6; // denormal
                else if (exponent == 0x7fffU &&
                         significand == 0x8000000000000000ULL)
                    c3c2c0 = 3; // infinity
                else if (exponent == 0x7fffU) c3c2c0 = 1; // NaN
                else if ((significand & (1ULL << 63)) != 0) c3c2c0 = 2;
                else c3c2c0 = 0; // unsupported
            }
            status &= static_cast<uint16_t>(~((1U << 14) | (1U << 10) |
                                               (1U << 9) | (1U << 8)));
            if (c3c2c0 & 4U) status |= 1U << 14;
            if (c3c2c0 & 2U) status |= 1U << 10;
            if (c3c2c0 & 1U) status |= 1U << 8;
            if (sign) status |= 1U << 9;
        }
        regs[statusOffset] = status;
        regs[tagOffset] = tags;
        return std::nullopt;
    }

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
    case POp::INT_NOT: {
        auto a = in(op.in0);
        return a ? std::optional<uint64_t>(maskVal(~*a, dst()))
                 : std::nullopt;
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
    case POp::INT_PDEP:
    case POp::INT_PEXT: {
        auto source = in(op.in0), mask = in(op.in1);
        if (!source || !mask || !vo) return std::nullopt;
        const int bits = vo->size * 8;
        uint64_t result = 0;
        uint64_t sourceBit = 1;
        uint64_t outputBit = 1;
        uint64_t remainingMask = maskVal(*mask, vo->size);
        if (op.op == POp::INT_PDEP) {
            while (remainingMask) {
                const uint64_t selected = remainingMask & (~remainingMask + 1);
                if (*source & sourceBit) result |= selected;
                remainingMask &= remainingMask - 1;
                sourceBit <<= 1;
            }
        } else {
            while (remainingMask) {
                const uint64_t selected = remainingMask & (~remainingMask + 1);
                if (*source & selected) result |= outputBit;
                remainingMask &= remainingMask - 1;
                outputBit <<= 1;
            }
        }
        return bits >= 64 ? result : result & ((1ULL << bits) - 1);
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
        if (!vo) return std::nullopt;
        const int floatBits = op.aux & 0x7fff;
        const auto sourceBytes = wideValue(op.in0);
        if (!sourceBytes) return std::nullopt;
        const auto decoded = decodeFloatValue(*sourceBytes, floatBits);
        if (!decoded) return std::nullopt;
        const long double value = *decoded;
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
        const int sourceBits = op.aux & 0xff;
        const int destinationBits = (op.aux >> 8) & 0x7f;
        const auto sourceBytes = wideValue(op.in0);
        if (!sourceBytes || destinationBits > 64) return std::nullopt;
        const auto decoded = decodeFloatValue(*sourceBytes, sourceBits);
        if (!decoded) return std::nullopt;
        const auto encoded = encodeFloatValue(*decoded, destinationBits);
        uint64_t result = 0;
        std::memcpy(&result, encoded.data(),
                    std::min<size_t>(sizeof(result), encoded.size()));
        return result;
    }
    case POp::INT_BSWAP: {
        auto value = in(op.in0);
        if (!value) return std::nullopt;
        const int bytes = dst();
        uint64_t result = 0;
        for (int byte = 0; byte < bytes; ++byte)
            result |= ((*value >> (byte * 8)) & 0xffU)
                      << ((bytes - 1 - byte) * 8);
        return result;
    }
    case POp::INT_CRC32C: {
        auto crcValue = in(op.in0), source = in(op.in1);
        if (!crcValue || !source || op.aux == 0 || op.aux > 8)
            return std::nullopt;
        uint32_t crc = static_cast<uint32_t>(*crcValue);
        for (unsigned byte = 0; byte < op.aux; ++byte) {
            crc ^= static_cast<uint8_t>(*source >> (byte * 8));
            for (unsigned bit = 0; bit < 8; ++bit)
                crc = (crc >> 1) ^ ((crc & 1U) ? 0x82f63b78U : 0U);
        }
        return crc;
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
        const int laneBits = (op.aux & 0x7fff) ? (op.aux & 0x7fff) : 64;
        if (laneBits == 80 &&
            (op.op == POp::FLOAT_EQUAL || op.op == POp::FLOAT_NOTEQUAL ||
             op.op == POp::FLOAT_LESS || op.op == POp::FLOAT_LESSEQUAL ||
             op.op == POp::FLOAT_NAN)) {
            const auto aBytes = wideValue(op.in0);
            const auto bBytes = wideValue(op.in1);
            if (!aBytes || !bBytes) return std::nullopt;
            const auto x = decodeFloatValue(*aBytes, 80);
            const auto y = decodeFloatValue(*bBytes, 80);
            if (!x || !y) return std::nullopt;
            switch (op.op) {
            case POp::FLOAT_EQUAL:
                return !std::isnan(*x) && !std::isnan(*y) && *x == *y;
            case POp::FLOAT_NOTEQUAL:
                return std::isnan(*x) || std::isnan(*y) || *x != *y;
            case POp::FLOAT_LESS:
                return !std::isnan(*x) && !std::isnan(*y) && *x < *y;
            case POp::FLOAT_LESSEQUAL:
                return !std::isnan(*x) && !std::isnan(*y) && *x <= *y;
            case POp::FLOAT_NAN:
                return std::isnan(*x) || std::isnan(*y);
            default: break;
            }
        }
        auto a = floating(op.in0);
        auto b = floating(op.in1);
        if (!a || (op.op != POp::FLOAT_NEG && op.op != POp::FLOAT_ABS &&
                   op.op != POp::FLOAT_SQRT && op.op != POp::FLOAT_NAN && !b))
            return std::nullopt;
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

    case POp::SIMD_EXTRACT: {
        const auto source = wideValue(op.in0);
        const auto index = in(op.in1);
        if (!source || !index || !vo) return std::nullopt;
        const size_t laneBytes = static_cast<size_t>((op.aux & 0xff) / 8);
        if (!laneBytes || laneBytes > 8) return std::nullopt;
        const size_t lanes = source->size() / laneBytes;
        if (!lanes) return std::nullopt;
        const size_t at = (static_cast<size_t>(*index) % lanes) * laneBytes;
        if (at > source->size() || laneBytes > source->size() - at)
            return std::nullopt;
        uint64_t value = 0;
        std::memcpy(&value, source->data() + at, laneBytes);
        return maskVal(value, vo->size);
    }

    case POp::SIMD_COMPARE_CHECK: {
        const auto left = wideValue(op.in0), right = wideValue(op.in1);
        const unsigned laneBits = op.aux & 0xffU;
        const bool quiet = (op.aux & 0x0100U) != 0;
        if (!left || !right || (laneBits != 32 && laneBits != 64) ||
            left->size() < laneBits / 8 || right->size() < laneBits / 8)
            return std::nullopt;
        auto classify = [&](const std::vector<uint8_t>& bytes) {
            bool nan = false, signaling = false;
            if (laneBits == 32) {
                uint32_t bits = 0;
                std::memcpy(&bits, bytes.data(), 4);
                nan = (bits & 0x7f800000U) == 0x7f800000U &&
                      (bits & 0x007fffffU) != 0;
                signaling = nan && (bits & 0x00400000U) == 0;
            } else {
                uint64_t bits = 0;
                std::memcpy(&bits, bytes.data(), 8);
                nan = (bits & 0x7ff0000000000000ULL) ==
                          0x7ff0000000000000ULL &&
                      (bits & 0x000fffffffffffffULL) != 0;
                signaling = nan && (bits & 0x0008000000000000ULL) == 0;
            }
            return std::pair<bool, bool>{nan, signaling};
        };
        const auto lhs = classify(*left), rhs = classify(*right);
        const bool invalid = quiet ? (lhs.second || rhs.second)
                                   : (lhs.first || rhs.first);
        if (invalid) {
            mxcsr |= 1U;
            if ((mxcsr & (1U << 7)) == 0) {
                fault = FaultInfo{X86Fault::SimdFloatingPoint, 0, insn_.addr};
                suppressRemaining_ = true;
            }
        }
        return std::nullopt;
    }

    case POp::SIMD_STRING_COMPARE: {
        const auto left = wideValue(op.in0), right = wideValue(op.in1);
        if (!left || !right) return std::nullopt;
        const unsigned control = op.aux & 0xffU;
        const bool words = (control & 1U) != 0;
        const bool signedElements = (control & 2U) != 0;
        const size_t elementBytes = words ? 2 : 1;
        const size_t maximum = words ? 8 : 16;
        if (left->size() < maximum * elementBytes ||
            right->size() < maximum * elementBytes)
            return std::nullopt;
        int64_t a[16] = {}, b[16] = {};
        for (size_t lane = 0; lane < maximum; ++lane) {
            uint16_t x = 0, y = 0;
            std::memcpy(&x, left->data() + lane * elementBytes, elementBytes);
            std::memcpy(&y, right->data() + lane * elementBytes, elementBytes);
            if (signedElements) {
                a[lane] = words ? static_cast<int16_t>(x)
                                : static_cast<int8_t>(x);
                b[lane] = words ? static_cast<int16_t>(y)
                                : static_cast<int8_t>(y);
            } else {
                a[lane] = x;
                b[lane] = y;
            }
        }
        size_t lengthA = maximum, lengthB = maximum;
        const bool explicitLengths = (op.aux & 0x0800U) != 0;
        if (explicitLengths) {
            const auto packedLengths = in(op.in2);
            if (!packedLengths) return std::nullopt;
            auto absoluteLength = [&](uint32_t raw) {
                const int64_t signedLength = static_cast<int32_t>(raw);
                const uint64_t magnitude = signedLength < 0
                    ? static_cast<uint64_t>(-signedLength)
                    : static_cast<uint64_t>(signedLength);
                return std::min<size_t>(maximum,
                                        static_cast<size_t>(magnitude));
            };
            lengthA = absoluteLength(static_cast<uint32_t>(*packedLengths));
            lengthB = absoluteLength(static_cast<uint32_t>(*packedLengths >> 32));
        } else {
            for (size_t lane = 0; lane < maximum; ++lane) {
                if (a[lane] == 0 && lengthA == maximum) lengthA = lane;
                if (b[lane] == 0 && lengthB == maximum) lengthB = lane;
            }
        }

        uint32_t intRes1 = 0;
        const unsigned aggregation = (control >> 2) & 3U;
        if (aggregation == 0) { // equal any
            for (size_t j = 0; j < lengthB; ++j)
                for (size_t i = 0; i < lengthA; ++i)
                    if (a[i] == b[j]) {
                        intRes1 |= 1U << j;
                        break;
                    }
        } else if (aggregation == 1) { // ranges
            for (size_t j = 0; j < lengthB; ++j)
                for (size_t i = 0; i + 1 < lengthA; i += 2)
                    if (a[i] <= b[j] && b[j] <= a[i + 1]) {
                        intRes1 |= 1U << j;
                        break;
                    }
        } else if (aggregation == 2) { // equal each
            for (size_t i = 0; i < maximum; ++i) {
                const bool validA = i < lengthA, validB = i < lengthB;
                if ((validA && validB && a[i] == b[i]) ||
                    (!validA && !validB))
                    intRes1 |= 1U << i;
            }
        } else { // equal ordered
            for (size_t start = 0; start < maximum; ++start) {
                bool match = true;
                for (size_t i = 0; i < lengthA; ++i) {
                    if (start + i >= lengthB || a[i] != b[start + i]) {
                        match = false;
                        break;
                    }
                }
                if (match) intRes1 |= 1U << start;
            }
        }
        const uint32_t elementMask = (1U << maximum) - 1U;
        const uint32_t validBMask = lengthB == maximum
            ? elementMask : ((1U << lengthB) - 1U);
        uint32_t intRes2 = intRes1 & elementMask;
        const unsigned polarity = (control >> 4) & 3U;
        if (polarity == 1) intRes2 = (~intRes1) & elementMask;
        else if (polarity == 3) intRes2 = intRes1 ^ validBMask;

        const unsigned query = (op.aux >> 8) & 7U;
        switch (query) {
        case 0: return intRes2;
        case 1:
            if (!intRes2) return maximum;
            if ((control & 0x40U) == 0) {
                unsigned index = 0;
                while (((intRes2 >> index) & 1U) == 0) ++index;
                return index;
            } else {
                unsigned index = static_cast<unsigned>(maximum - 1);
                while (((intRes2 >> index) & 1U) == 0) --index;
                return index;
            }
        case 2: return intRes2 != 0;         // CF
        case 3: return lengthB < maximum;    // ZF
        case 4: return lengthA < maximum;    // SF
        case 5: return intRes2 & 1U;         // OF
        default: return 0;                   // AF/PF are cleared
        }
    }

    case POp::SIMD_TEST: {
        const auto left = wideValue(op.in0), right = wideValue(op.in1);
        if (!left || !right || left->size() != right->size())
            return std::nullopt;
        bool andIsZero = true;
        bool andNotIsZero = true;
        for (size_t byte = 0; byte < left->size(); ++byte) {
            andIsZero &= ((*left)[byte] & (*right)[byte]) == 0;
            andNotIsZero &= (static_cast<uint8_t>(~(*left)[byte]) &
                             (*right)[byte]) == 0;
        }
        return (op.aux & 1U) ? andNotIsZero : andIsZero;
    }

    case POp::SIMD_MOVEMASK: {
        const auto source = wideValue(op.in0);
        if (!source) return std::nullopt;
        const unsigned laneBits = op.aux & 0xffU;
        const size_t laneBytes = laneBits / 8;
        if (!laneBytes || laneBytes > 8 || source->size() % laneBytes)
            return std::nullopt;
        uint64_t result = 0;
        const size_t lanes = std::min<size_t>(64, source->size() / laneBytes);
        for (size_t lane = 0; lane < lanes; ++lane) {
            const uint8_t highByte = (*source)[lane * laneBytes + laneBytes - 1];
            result |= static_cast<uint64_t>(highByte >> 7) << lane;
        }
        return result;
    }

    case POp::SIMD_COMPARE_MASK: {
        const auto left = wideValue(op.in0);
        const auto right = wideValue(op.in1);
        const auto predicateValue = in(op.in2);
        if (!left || !right || !predicateValue) return std::nullopt;
        const int laneBits = op.aux & 0xff;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        if (!laneBytes || laneBytes > 8 || left->size() % laneBytes ||
            right->size() < left->size())
            return std::nullopt;
        const bool signedCompare = (op.aux & 0x0100) != 0;
        const unsigned predicate = static_cast<unsigned>(*predicateValue & 7U);
        uint64_t result = 0;
        const size_t lanes = std::min<size_t>(64, left->size() / laneBytes);
        for (size_t lane = 0; lane < lanes; ++lane) {
            uint64_t x = 0, y = 0;
            std::memcpy(&x, left->data() + lane * laneBytes, laneBytes);
            std::memcpy(&y, right->data() + lane * laneBytes, laneBytes);
            const bool equal = x == y;
            const bool less = signedCompare
                ? static_cast<int64_t>(sextVal(x, laneBits)) <
                      static_cast<int64_t>(sextVal(y, laneBits))
                : x < y;
            bool truth = false;
            switch (predicate) {
            case 0: truth = equal; break;
            case 1: truth = less; break;
            case 2: truth = less || equal; break;
            case 3: truth = false; break;
            case 4: truth = !equal; break;
            case 5: truth = !less; break;
            case 6: truth = !(less || equal); break;
            case 7: truth = true; break;
            }
            if (truth) result |= 1ULL << lane;
        }
        return result;
    }

    case POp::SIMD_MASK:
    case POp::FLOAT_ROUND:
    case POp::FLOAT_SIN:
    case POp::FLOAT_COS:
    case POp::FLOAT_TAN:
    case POp::FLOAT_ATAN2:
    case POp::FLOAT_LOG2:
    case POp::FLOAT_EXP2:
    case POp::FLOAT_REMAINDER:
    case POp::FLOAT_SCALE:
    case POp::SIMD_COMPARE:
    case POp::SIMD_ADDSUB:
    case POp::SIMD_BLEND:
    case POp::SIMD_FP_COMPARE:
    case POp::SIMD_HORIZONTAL:
    case POp::SIMD_INT2FLOAT:
    case POp::SIMD_FLOAT2INT:
    case POp::SIMD_FLOAT2FLOAT:
    case POp::SIMD_DOT_PRODUCT:
    case POp::SIMD_ABS:
    case POp::SIMD_INT_HORIZONTAL:
    case POp::SIMD_STRING_MASK:
    case POp::SIMD_MULTIPLY:
    case POp::SIMD_SIGN:
    case POp::SIMD_BYTE_SHIFT:
    case POp::SIMD_APPROX:
    case POp::SIMD_ROUND:
    case POp::SIMD_PERMUTE128:
    case POp::SIMD_EXTEND:
    case POp::SIMD_ZERO_UPPER:
    case POp::SIMD_SATURATE:
    case POp::SIMD_UNPACK:
    case POp::SIMD_PACK:
    case POp::SIMD_SHUFFLE:
    case POp::SIMD_SHIFT:
    case POp::SIMD_INSERT:
    case POp::SIMD_BROADCAST:
    case POp::SIMD_GATHER:
    case POp::SIMD_SCATTER:
    case POp::SIMD_AVERAGE:
    case POp::SIMD_MINMAX:
    case POp::SIMD_SAD:
    case POp::AES_ENC:
    case POp::AES_DEC:
    case POp::AES_IMC:
    case POp::AES_KEYGEN:
    case POp::GF2P8_MUL:
    case POp::GF2P8_AFFINE:
    case POp::GF2P8_AFFINE_INV:
    case POp::CARRYLESS_MULT:
    case POp::SHA1_MSG1:
    case POp::SHA1_MSG2:
    case POp::SHA1_NEXTE:
    case POp::SHA1_RNDS4:
    case POp::SHA256_MSG1:
    case POp::SHA256_MSG2:
    case POp::SHA256_RNDS2:
    case POp::X87_CONSTANT:
    case POp::UNIMPLEMENTED:
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> PcodeEvaluator::evalWideOp(const PcodeOp& op) {
    const Varnode* out = insn_.find(op.out);
    const size_t size = out ? static_cast<size_t>(out->size) : 0;
    if (op.op == POp::X87_CONSTANT) {
        long double value = 0;
        switch (op.aux) {
        case 0: value = 1.0L; break;
        case 1: value = 0.0L; break;
        case 2: value = std::log2(10.0L); break;
        case 3: value = std::log2(std::exp(1.0L)); break;
        case 4: value = std::acos(-1.0L); break;
        case 5: value = std::log10(2.0L); break;
        case 6: value = std::log(2.0L); break;
        default: return std::nullopt;
        }
        std::vector<uint8_t> result(size, 0);
        const auto encoded = encodeFloatValue(value, 80);
        std::copy(encoded.begin(), encoded.end(), result.begin());
        return result;
    }
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
    if (op.op == POp::SIMD_MASK) {
        auto computed = wideValue(op.in0);
        auto previous = wideValue(op.in1);
        auto mask = varnodeValue(op.in2);
        if (!computed || !previous || !mask) return std::nullopt;
        computed->resize(size, 0);
        previous->resize(size, 0);
        const int laneBits = (op.aux & 0x7fff) ? (op.aux & 0x7fff) : 8;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        if (!laneBytes || size % laneBytes) return std::nullopt;
        const bool zeroMasked = (op.aux & 0x8000) != 0;
        for (size_t lane = 0; lane < size / laneBytes; ++lane) {
            if (lane < 64 && ((*mask >> lane) & 1)) continue;
            for (size_t byte = 0; byte < laneBytes; ++byte)
                (*computed)[lane * laneBytes + byte] =
                    zeroMasked ? 0 : (*previous)[lane * laneBytes + byte];
        }
        return computed;
    }
    if (op.op == POp::SIMD_ADDSUB || op.op == POp::SIMD_BLEND) {
        auto left = wideValue(op.in0), right = wideValue(op.in1);
        if (!left || !right || !out) return std::nullopt;
        left->resize(size, 0); right->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const size_t laneBytes = laneBits / 8;
        if (op.op == POp::SIMD_BLEND) {
            if (!laneBytes || laneBytes > 8 || size % laneBytes)
                return std::nullopt;
            const auto immediate = varnodeValue(op.in2);
            if (!immediate) return std::nullopt;
            for (size_t lane = 0; lane < size / laneBytes; ++lane)
                if ((*immediate >> lane) & 1U)
                    std::memcpy(left->data() + lane * laneBytes,
                                right->data() + lane * laneBytes, laneBytes);
            return left;
        }
        if ((laneBits != 32 && laneBits != 64) || size % laneBytes)
            return std::nullopt;
        for (size_t lane = 0; lane < size / laneBytes; ++lane) {
            if (laneBits == 32) {
                float a = 0, b = 0;
                std::memcpy(&a, left->data() + lane * 4, 4);
                std::memcpy(&b, right->data() + lane * 4, 4);
                const float result = (lane & 1U) ? a + b : a - b;
                std::memcpy(left->data() + lane * 4, &result, 4);
            } else {
                double a = 0, b = 0;
                std::memcpy(&a, left->data() + lane * 8, 8);
                std::memcpy(&b, right->data() + lane * 8, 8);
                const double result = (lane & 1U) ? a + b : a - b;
                std::memcpy(left->data() + lane * 8, &result, 8);
            }
        }
        return left;
    }
    if (op.op == POp::SIMD_FP_COMPARE) {
        auto left = wideValue(op.in0), right = wideValue(op.in1);
        const auto predicateValue = varnodeValue(op.in2);
        if (!left || !right || !predicateValue || !out) return std::nullopt;
        left->resize(size, 0); right->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const size_t laneBytes = laneBits / 8;
        const bool scalar = (op.aux & 0x8000U) != 0;
        if ((laneBits != 32 && laneBits != 64) || size % laneBytes)
            return std::nullopt;
        const size_t lanes = scalar ? 1 : size / laneBytes;
        const unsigned predicate = static_cast<unsigned>(*predicateValue & 7U);
        for (size_t lane = 0; lane < lanes; ++lane) {
            long double a = 0, b = 0;
            if (laneBits == 32) {
                float x = 0, y = 0;
                std::memcpy(&x, left->data() + lane * 4, 4);
                std::memcpy(&y, right->data() + lane * 4, 4);
                a = x; b = y;
            } else {
                double x = 0, y = 0;
                std::memcpy(&x, left->data() + lane * 8, 8);
                std::memcpy(&y, right->data() + lane * 8, 8);
                a = x; b = y;
            }
            const bool unordered = std::isnan(a) || std::isnan(b);
            bool truth = false;
            switch (predicate) {
            case 0: truth = !unordered && a == b; break;
            case 1: truth = !unordered && a < b; break;
            case 2: truth = !unordered && a <= b; break;
            case 3: truth = unordered; break;
            case 4: truth = unordered || a != b; break;
            case 5: truth = unordered || !(a < b); break;
            case 6: truth = unordered || !(a <= b); break;
            case 7: truth = !unordered; break;
            }
            std::memset(left->data() + lane * laneBytes,
                        truth ? 0xff : 0x00, laneBytes);
        }
        return left;
    }
    if (op.op == POp::SIMD_HORIZONTAL) {
        auto left = wideValue(op.in0), right = wideValue(op.in1);
        if (!left || !right || !out || size % 16) return std::nullopt;
        left->resize(size, 0); right->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const bool subtract = (op.aux & 0x0100U) != 0;
        if (laneBits != 32 && laneBits != 64) return std::nullopt;
        std::vector<uint8_t> result(size, 0);
        for (size_t block = 0; block < size; block += 16) {
            if (laneBits == 32) {
                float a[4] = {}, b[4] = {}, z[4] = {};
                std::memcpy(a, left->data() + block, 16);
                std::memcpy(b, right->data() + block, 16);
                z[0] = subtract ? a[0] - a[1] : a[0] + a[1];
                z[1] = subtract ? a[2] - a[3] : a[2] + a[3];
                z[2] = subtract ? b[0] - b[1] : b[0] + b[1];
                z[3] = subtract ? b[2] - b[3] : b[2] + b[3];
                std::memcpy(result.data() + block, z, 16);
            } else {
                double a[2] = {}, b[2] = {}, z[2] = {};
                std::memcpy(a, left->data() + block, 16);
                std::memcpy(b, right->data() + block, 16);
                z[0] = subtract ? a[0] - a[1] : a[0] + a[1];
                z[1] = subtract ? b[0] - b[1] : b[0] + b[1];
                std::memcpy(result.data() + block, z, 16);
            }
        }
        return result;
    }
    if (op.op == POp::SIMD_INT2FLOAT ||
        op.op == POp::SIMD_FLOAT2INT ||
        op.op == POp::SIMD_FLOAT2FLOAT) {
        auto source = wideValue(op.in0);
        if (!source || !out) return std::nullopt;
        const unsigned sourceBits = op.aux & 0xffU;
        const unsigned destinationBits = (op.aux >> 8) & 0x7fU;
        const size_t sourceBytes = sourceBits / 8;
        const size_t destinationBytes = destinationBits / 8;
        if ((sourceBits != 32 && sourceBits != 64) ||
            (destinationBits != 32 && destinationBits != 64) ||
            !sourceBytes || !destinationBytes)
            return std::nullopt;
        const size_t lanes = std::min(source->size() / sourceBytes,
                                      size / destinationBytes);
        std::vector<uint8_t> result(size, 0);
        bool invalid = false;
        bool inexact = false;
        const auto roundToInteger = [&](long double value) {
            if (op.op == POp::SIMD_FLOAT2INT && (op.aux & 0x8000U))
                return std::trunc(value);
            switch ((mxcsr >> 13) & 3U) {
            case 1: return std::floor(value);
            case 2: return std::ceil(value);
            case 3: return std::trunc(value);
            default: {
                const long double lower = std::floor(value);
                const long double fraction = value - lower;
                if (fraction < 0.5L) return lower;
                if (fraction > 0.5L) return lower + 1.0L;
                return std::fmod(lower, 2.0L) == 0.0L ? lower
                                                       : lower + 1.0L;
            }
            }
        };
        for (size_t lane = 0; lane < lanes; ++lane) {
            const uint8_t* input = source->data() + lane * sourceBytes;
            uint8_t* output = result.data() + lane * destinationBytes;
            if (op.op == POp::SIMD_INT2FLOAT) {
                int64_t integer = 0;
                if (sourceBits == 32) {
                    int32_t value = 0;
                    std::memcpy(&value, input, sizeof(value));
                    integer = value;
                } else {
                    std::memcpy(&integer, input, sizeof(integer));
                }
                if (destinationBits == 32) {
                    const float converted = static_cast<float>(integer);
                    std::memcpy(output, &converted, sizeof(converted));
                    inexact |= static_cast<long double>(converted) != integer;
                } else {
                    const double converted = static_cast<double>(integer);
                    std::memcpy(output, &converted, sizeof(converted));
                    inexact |= static_cast<long double>(converted) != integer;
                }
                continue;
            }

            long double floating = 0;
            if (sourceBits == 32) {
                float value = 0;
                std::memcpy(&value, input, sizeof(value));
                floating = value;
            } else {
                double value = 0;
                std::memcpy(&value, input, sizeof(value));
                floating = value;
            }
            if (op.op == POp::SIMD_FLOAT2FLOAT) {
                if (destinationBits == 32) {
                    const float converted = static_cast<float>(floating);
                    std::memcpy(output, &converted, sizeof(converted));
                    inexact |= std::isfinite(floating) &&
                               static_cast<long double>(converted) != floating;
                } else {
                    const double converted = static_cast<double>(floating);
                    std::memcpy(output, &converted, sizeof(converted));
                }
                continue;
            }

            const long double rounded = roundToInteger(floating);
            const long double limit = std::ldexp(1.0L, destinationBits - 1);
            if (!std::isfinite(rounded) || rounded < -limit || rounded >= limit) {
                invalid = true;
                const uint64_t indefinite = 1ULL << (destinationBits - 1);
                std::memcpy(output, &indefinite, destinationBytes);
            } else {
                const int64_t integer = static_cast<int64_t>(rounded);
                std::memcpy(output, &integer, destinationBytes);
                inexact |= rounded != floating;
            }
        }
        if (invalid) mxcsr |= 1U;
        if (inexact) mxcsr |= 1U << 5;
        if ((invalid && (mxcsr & (1U << 7)) == 0) ||
            (!invalid && inexact && (mxcsr & (1U << 12)) == 0)) {
            fault = FaultInfo{X86Fault::SimdFloatingPoint, 0, insn_.addr};
            suppressRemaining_ = true;
            return std::nullopt;
        }
        return result;
    }
    if (op.op == POp::SIMD_DOT_PRODUCT) {
        auto left = wideValue(op.in0), right = wideValue(op.in1);
        const auto immediate = varnodeValue(op.in2);
        if (!left || !right || !immediate || !out || size % 16)
            return std::nullopt;
        left->resize(size, 0);
        right->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        if (laneBits != 32 && laneBits != 64) return std::nullopt;
        std::vector<uint8_t> result(size, 0);
        for (size_t block = 0; block < size; block += 16) {
            if (laneBits == 32) {
                float a[4] = {}, b[4] = {};
                std::memcpy(a, left->data() + block, 16);
                std::memcpy(b, right->data() + block, 16);
                float sum = 0;
                for (unsigned lane = 0; lane < 4; ++lane)
                    if ((*immediate >> (lane + 4)) & 1U)
                        sum += a[lane] * b[lane];
                for (unsigned lane = 0; lane < 4; ++lane)
                    if ((*immediate >> lane) & 1U)
                        std::memcpy(result.data() + block + lane * 4,
                                    &sum, sizeof(sum));
            } else {
                double a[2] = {}, b[2] = {};
                std::memcpy(a, left->data() + block, 16);
                std::memcpy(b, right->data() + block, 16);
                double sum = 0;
                for (unsigned lane = 0; lane < 2; ++lane)
                    if ((*immediate >> (lane + 4)) & 1U)
                        sum += a[lane] * b[lane];
                for (unsigned lane = 0; lane < 2; ++lane)
                    if ((*immediate >> lane) & 1U)
                        std::memcpy(result.data() + block + lane * 8,
                                    &sum, sizeof(sum));
            }
        }
        return result;
    }
    if (op.op == POp::SIMD_INT_HORIZONTAL) {
        auto left = wideValue(op.in0), right = wideValue(op.in1);
        if (!left || !right || !out || size % 16) return std::nullopt;
        left->resize(size, 0);
        right->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const bool subtract = (op.aux & 0x0100U) != 0;
        const bool saturate = (op.aux & 0x0200U) != 0;
        const size_t laneBytes = laneBits / 8;
        if ((laneBits != 16 && laneBits != 32) || !laneBytes)
            return std::nullopt;
        std::vector<uint8_t> result(size, 0);
        const size_t lanesPerBlock = 16 / laneBytes;
        const uint64_t mask = (1ULL << laneBits) - 1U;
        for (size_t block = 0; block < size; block += 16) {
            size_t outputLane = 0;
            for (const auto* input : {&*left, &*right}) {
                for (size_t lane = 0; lane < lanesPerBlock; lane += 2) {
                    uint64_t rawA = 0, rawB = 0;
                    std::memcpy(&rawA, input->data() + block + lane * laneBytes,
                                laneBytes);
                    std::memcpy(&rawB,
                                input->data() + block + (lane + 1) * laneBytes,
                                laneBytes);
                    const int64_t a = static_cast<int64_t>(sextVal(rawA, laneBits));
                    const int64_t b = static_cast<int64_t>(sextVal(rawB, laneBits));
                    int64_t value = subtract ? a - b : a + b;
                    if (saturate) {
                        const int64_t low = -(1LL << (laneBits - 1));
                        const int64_t high = (1LL << (laneBits - 1)) - 1;
                        value = std::max(low, std::min(high, value));
                    }
                    const uint64_t encoded = static_cast<uint64_t>(value) & mask;
                    std::memcpy(result.data() + block + outputLane * laneBytes,
                                &encoded, laneBytes);
                    ++outputLane;
                }
            }
        }
        return result;
    }
    if (op.op == POp::SIMD_STRING_MASK) {
        const auto bits = varnodeValue(op.in0);
        if (!bits || !out || size != 16) return std::nullopt;
        const unsigned control = op.aux & 0xffU;
        const bool words = (control & 1U) != 0;
        const size_t elementBytes = words ? 2 : 1;
        const size_t maximum = words ? 8 : 16;
        std::vector<uint8_t> result(size, 0);
        if ((control & 0x40U) == 0) {
            const uint16_t compact = static_cast<uint16_t>(*bits);
            std::memcpy(result.data(), &compact, sizeof(compact));
        } else {
            for (size_t lane = 0; lane < maximum; ++lane)
                if ((*bits >> lane) & 1U)
                    std::memset(result.data() + lane * elementBytes, 0xff,
                                elementBytes);
        }
        return result;
    }
    if (op.op == POp::SIMD_MULTIPLY) {
        auto left = wideValue(op.in0), right = wideValue(op.in1);
        if (!left || !right || !out || size % 16) return std::nullopt;
        left->resize(size, 0);
        right->resize(size, 0);
        const unsigned mode = (op.aux >> 8) & 0x7fU;
        std::vector<uint8_t> result(size, 0);
        if (mode == 1) { // PMADDWD: signed word products, pairwise dword sum
            for (size_t block = 0; block < size; block += 16)
                for (size_t pair = 0; pair < 4; ++pair) {
                    int16_t a[2] = {}, b[2] = {};
                    std::memcpy(a, left->data() + block + pair * 4, 4);
                    std::memcpy(b, right->data() + block + pair * 4, 4);
                    const uint32_t sum = static_cast<uint32_t>(
                        static_cast<int64_t>(a[0]) * b[0] +
                        static_cast<int64_t>(a[1]) * b[1]);
                    std::memcpy(result.data() + block + pair * 4, &sum, 4);
                }
            return result;
        }
        if (mode == 2) { // PMADDUBSW: unsigned*signed bytes, saturated words
            for (size_t block = 0; block < size; block += 16)
                for (size_t pair = 0; pair < 8; ++pair) {
                    const size_t at = block + pair * 2;
                    const int value = static_cast<int>((*left)[at]) *
                                          static_cast<int8_t>((*right)[at]) +
                                      static_cast<int>((*left)[at + 1]) *
                                          static_cast<int8_t>((*right)[at + 1]);
                    const int16_t saturated = static_cast<int16_t>(
                        std::max(-32768, std::min(32767, value)));
                    std::memcpy(result.data() + at, &saturated, 2);
                }
            return result;
        }
        if (mode == 3) { // PMULDQ: signed even dwords to signed qwords
            for (size_t block = 0; block < size; block += 16)
                for (size_t lane = 0; lane < 2; ++lane) {
                    int32_t a = 0, b = 0;
                    std::memcpy(&a, left->data() + block + lane * 8, 4);
                    std::memcpy(&b, right->data() + block + lane * 8, 4);
                    const int64_t product = static_cast<int64_t>(a) * b;
                    std::memcpy(result.data() + block + lane * 8,
                                &product, 8);
                }
            return result;
        }
        if (mode == 4) { // PMULHRSW: rounded signed high word
            for (size_t at = 0; at < size; at += 2) {
                int16_t a = 0, b = 0;
                std::memcpy(&a, left->data() + at, 2);
                std::memcpy(&b, right->data() + at, 2);
                const int32_t product = static_cast<int32_t>(a) * b;
                const uint16_t rounded = static_cast<uint16_t>(
                    (product + 0x4000) >> 15);
                std::memcpy(result.data() + at, &rounded, 2);
            }
            return result;
        }
        return std::nullopt;
    }
    if (op.op == POp::SIMD_SIGN) {
        auto values = wideValue(op.in0), signs = wideValue(op.in1);
        if (!values || !signs || !out) return std::nullopt;
        values->resize(size, 0);
        signs->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const size_t laneBytes = laneBits / 8;
        if ((laneBits != 8 && laneBits != 16 && laneBits != 32) ||
            !laneBytes || size % laneBytes)
            return std::nullopt;
        const uint64_t mask = (1ULL << laneBits) - 1U;
        for (size_t at = 0; at < size; at += laneBytes) {
            uint64_t value = 0, sign = 0;
            std::memcpy(&value, values->data() + at, laneBytes);
            std::memcpy(&sign, signs->data() + at, laneBytes);
            const int64_t signedControl = static_cast<int64_t>(sextVal(sign, laneBits));
            if (signedControl == 0) value = 0;
            else if (signedControl < 0) value = (~value + 1U) & mask;
            std::memcpy(values->data() + at, &value, laneBytes);
        }
        return values;
    }
    if (op.op == POp::SIMD_BYTE_SHIFT) {
        auto source = wideValue(op.in0);
        const auto countValue = varnodeValue(op.in1);
        if (!source || !countValue || !out || size % 16)
            return std::nullopt;
        source->resize(size, 0);
        std::vector<uint8_t> result(size, 0);
        const size_t count = static_cast<size_t>(*countValue & 0xffU);
        const bool right = (op.aux & 1U) != 0;
        if (count >= 16) return result;
        for (size_t block = 0; block < size; block += 16) {
            if (right)
                std::memcpy(result.data() + block,
                            source->data() + block + count, 16 - count);
            else
                std::memcpy(result.data() + block + count,
                            source->data() + block, 16 - count);
        }
        return result;
    }
    if (op.op == POp::SIMD_APPROX) {
        auto source = wideValue(op.in0);
        if (!source || !out) return std::nullopt;
        source->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const bool reciprocalSquareRoot = (op.aux & 0x0100U) != 0;
        const bool scalar = (op.aux & 0x8000U) != 0;
        if (laneBits != 32 || size % 4) return std::nullopt;
        std::vector<uint8_t> result = *source;
        if (scalar) {
            if (auto base = wideValue(op.in1)) {
                result = std::move(*base);
                result.resize(size, 0);
            }
        }
        const size_t lanes = scalar ? 1 : size / 4;
        for (size_t lane = 0; lane < lanes; ++lane) {
            float value = 0;
            std::memcpy(&value, source->data() + lane * 4, 4);
            // Intel's approximate operations treat denormal inputs as signed
            // zero and do not report SIMD floating-point exceptions.
            if (std::fpclassify(value) == FP_SUBNORMAL)
                value = std::copysign(0.0f, value);
            const float computed = reciprocalSquareRoot
                ? 1.0f / std::sqrt(value) : 1.0f / value;
            std::memcpy(result.data() + lane * 4, &computed, 4);
        }
        return result;
    }
    if (op.op == POp::SIMD_ROUND) {
        auto source = wideValue(op.in0);
        const auto immediate = varnodeValue(op.in2);
        if (!source || !immediate || !out) return std::nullopt;
        source->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const bool scalar = (op.aux & 0x8000U) != 0;
        const size_t laneBytes = laneBits / 8;
        if ((laneBits != 32 && laneBits != 64) || size % laneBytes)
            return std::nullopt;
        std::vector<uint8_t> result = *source;
        if (scalar) {
            if (auto base = wideValue(op.in1)) {
                result = std::move(*base);
                result.resize(size, 0);
            }
        }
        const unsigned control = static_cast<unsigned>(*immediate & 0x0fU);
        const unsigned rounding = (control & 4U) ? ((mxcsr >> 13) & 3U)
                                                  : (control & 3U);
        const bool suppressPrecision = (control & 8U) != 0;
        bool inexact = false;
        auto roundedValue = [&](long double value) {
            switch (rounding) {
            case 1: return std::floor(value);
            case 2: return std::ceil(value);
            case 3: return std::trunc(value);
            default: {
                const long double lower = std::floor(value);
                const long double fraction = value - lower;
                if (fraction < 0.5L) return lower;
                if (fraction > 0.5L) return lower + 1.0L;
                return std::fmod(lower, 2.0L) == 0.0L ? lower
                                                       : lower + 1.0L;
            }
            }
        };
        const size_t lanes = scalar ? 1 : size / laneBytes;
        for (size_t lane = 0; lane < lanes; ++lane) {
            if (laneBits == 32) {
                float value = 0;
                std::memcpy(&value, source->data() + lane * 4, 4);
                float rounded = std::isfinite(value)
                    ? static_cast<float>(roundedValue(value)) : value;
                if (rounded == 0) rounded = std::copysign(0.0f, value);
                inexact |= std::isfinite(value) && rounded != value;
                std::memcpy(result.data() + lane * 4, &rounded, 4);
            } else {
                double value = 0;
                std::memcpy(&value, source->data() + lane * 8, 8);
                double rounded = std::isfinite(value)
                    ? static_cast<double>(roundedValue(value)) : value;
                if (rounded == 0) rounded = std::copysign(0.0, value);
                inexact |= std::isfinite(value) && rounded != value;
                std::memcpy(result.data() + lane * 8, &rounded, 8);
            }
        }
        if (inexact && !suppressPrecision) {
            mxcsr |= 1U << 5;
            if ((mxcsr & (1U << 12)) == 0) {
                fault = FaultInfo{X86Fault::SimdFloatingPoint, 0, insn_.addr};
                suppressRemaining_ = true;
                return std::nullopt;
            }
        }
        return result;
    }
    if (op.op == POp::SIMD_PERMUTE128) {
        auto left = wideValue(op.in0), right = wideValue(op.in1);
        const auto immediate = varnodeValue(op.in2);
        if (!left || !right || !immediate || !out || size != 32 ||
            left->size() < 32 || right->size() < 32)
            return std::nullopt;
        std::vector<uint8_t> result(32, 0);
        auto select = [&](unsigned control, uint8_t* destination) {
            const std::vector<uint8_t>* source = control >= 2 ? &*right : &*left;
            const size_t lane = control & 1U;
            std::memcpy(destination, source->data() + lane * 16, 16);
        };
        if ((*immediate & 0x08U) == 0)
            select(static_cast<unsigned>(*immediate & 3U), result.data());
        if ((*immediate & 0x80U) == 0)
            select(static_cast<unsigned>((*immediate >> 4) & 3U),
                   result.data() + 16);
        return result;
    }
    if (op.op == POp::SIMD_EXTEND) {
        auto source = wideValue(op.in0);
        if (!source || !out) return std::nullopt;
        const unsigned sourceBits = op.aux & 0xffU;
        const unsigned destinationBits = (op.aux >> 8) & 0x7fU;
        const bool signedExtend = (op.aux & 0x8000U) != 0;
        const size_t sourceBytes = sourceBits / 8;
        const size_t destinationBytes = destinationBits / 8;
        if (!sourceBytes || !destinationBytes || sourceBytes >= destinationBytes ||
            destinationBytes > 8 || size % destinationBytes)
            return std::nullopt;
        const size_t lanes = size / destinationBytes;
        if (source->size() < lanes * sourceBytes) return std::nullopt;
        std::vector<uint8_t> result(size, 0);
        for (size_t lane = 0; lane < lanes; ++lane) {
            uint64_t value = 0;
            std::memcpy(&value, source->data() + lane * sourceBytes,
                        sourceBytes);
            if (signedExtend)
                value = sextVal(value, static_cast<int>(sourceBits));
            std::memcpy(result.data() + lane * destinationBytes, &value,
                        destinationBytes);
        }
        return result;
    }
    if (op.op == POp::SIMD_ZERO_UPPER) {
        auto source = wideValue(op.in0);
        if (!source || !out || size != 32) return std::nullopt;
        source->resize(size, 0);
        std::fill(source->begin() + 16, source->end(), 0);
        return source;
    }
    if (op.op == POp::SIMD_COMPARE || op.op == POp::SIMD_SATURATE ||
        op.op == POp::SIMD_UNPACK || op.op == POp::SIMD_PACK) {
        auto a = wideValue(op.in0);
        auto b = wideValue(op.in1);
        if (!a || !b || !out) return std::nullopt;
        a->resize(size, 0);
        b->resize(size, 0);
        const int laneBits = op.aux & 0xff;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        if (!laneBytes || laneBytes > 8 || size % laneBytes)
            return std::nullopt;
        const uint64_t laneMask = laneBytes == 8
                                      ? ~0ULL : ((1ULL << laneBits) - 1);
        auto readLane = [&](const std::vector<uint8_t>& value, size_t at) {
            uint64_t lane = 0;
            std::memcpy(&lane, value.data() + at, laneBytes);
            return lane & laneMask;
        };
        if (op.op == POp::SIMD_COMPARE) {
            const bool greater = (op.aux & 0x0100) != 0;
            const bool signedCompare = (op.aux & 0x0200) != 0;
            for (size_t at = 0; at < size; at += laneBytes) {
                const uint64_t x = readLane(*a, at);
                const uint64_t y = readLane(*b, at);
                bool truth = x == y;
                if (greater) {
                    truth = signedCompare
                                ? static_cast<int64_t>(sextVal(x, laneBits)) >
                                      static_cast<int64_t>(sextVal(y, laneBits))
                                : x > y;
                }
                const uint64_t result = truth ? laneMask : 0;
                std::memcpy(a->data() + at, &result, laneBytes);
            }
            return a;
        }
        if (op.op == POp::SIMD_SATURATE) {
            const bool signedArithmetic = (op.aux & 0x0100) != 0;
            const bool subtract = (op.aux & 0x0200) != 0;
            if (laneBits > 32) return std::nullopt;
            for (size_t at = 0; at < size; at += laneBytes) {
                const uint64_t ux = readLane(*a, at);
                const uint64_t uy = readLane(*b, at);
                uint64_t result = 0;
                if (signedArithmetic) {
                    const int64_t x = static_cast<int64_t>(sextVal(ux, laneBits));
                    const int64_t y = static_cast<int64_t>(sextVal(uy, laneBits));
                    int64_t z = subtract ? x - y : x + y;
                    const int64_t low = -(1LL << (laneBits - 1));
                    const int64_t high = (1LL << (laneBits - 1)) - 1;
                    z = std::max(low, std::min(high, z));
                    result = static_cast<uint64_t>(z) & laneMask;
                } else {
                    if (subtract)
                        result = ux < uy ? 0 : ux - uy;
                    else {
                        const uint64_t z = ux + uy;
                        result = z > laneMask ? laneMask : z;
                    }
                }
                std::memcpy(a->data() + at, &result, laneBytes);
            }
            return a;
        }
        if (op.op == POp::SIMD_UNPACK) {
            const bool high = (op.aux & 0x8000) != 0;
            if (size % 16 || 16 % laneBytes) return std::nullopt;
            const size_t sourceLanes = 16 / laneBytes;
            const size_t first = high ? sourceLanes / 2 : 0;
            std::vector<uint8_t> result(size, 0);
            for (size_t block = 0; block < size; block += 16)
                for (size_t lane = 0; lane < sourceLanes / 2; ++lane) {
                    const size_t sourceAt = block + (first + lane) * laneBytes;
                    const size_t destinationAt = block + lane * 2 * laneBytes;
                    std::memcpy(result.data() + destinationAt,
                                a->data() + sourceAt, laneBytes);
                    std::memcpy(result.data() + destinationAt + laneBytes,
                                b->data() + sourceAt, laneBytes);
                }
            return result;
        }
        // PACK narrows signed source lanes to half-width destination lanes.
        // bit 8 selects unsigned saturation; otherwise signed saturation.
        const bool unsignedDestination = (op.aux & 0x0100) != 0;
        if (laneBytes < 2) return std::nullopt;
        const size_t destinationBytes = laneBytes / 2;
        const int destinationBits = laneBits / 2;
        std::vector<uint8_t> result(size, 0);
        if (size % 16) return std::nullopt;
        for (size_t block = 0; block < size; block += 16) {
            size_t outputAt = block;
            for (const std::vector<uint8_t>* source : {&*a, &*b}) {
                for (size_t at = block; at < block + 16; at += laneBytes) {
                    const int64_t value = static_cast<int64_t>(
                        sextVal(readLane(*source, at), laneBits));
                    uint64_t narrowed = 0;
                    if (unsignedDestination) {
                        const int64_t high = (1LL << destinationBits) - 1;
                        narrowed = static_cast<uint64_t>(
                            std::max<int64_t>(0, std::min(high, value)));
                    } else {
                        const int64_t low = -(1LL << (destinationBits - 1));
                        const int64_t high = (1LL << (destinationBits - 1)) - 1;
                        narrowed = static_cast<uint64_t>(
                            std::max(low, std::min(high, value)));
                    }
                    std::memcpy(result.data() + outputAt, &narrowed,
                                destinationBytes);
                    outputAt += destinationBytes;
                }
            }
        }
        return result;
    }
    if (op.op == POp::SIMD_ABS) {
        auto source = wideValue(op.in0);
        if (!source || !out) return std::nullopt;
        source->resize(size, 0);
        const unsigned laneBits = op.aux & 0xffU;
        const size_t laneBytes = laneBits / 8;
        if ((laneBits != 8 && laneBits != 16 && laneBits != 32) ||
            !laneBytes || size % laneBytes)
            return std::nullopt;
        const uint64_t mask = (1ULL << laneBits) - 1;
        for (size_t at = 0; at < size; at += laneBytes) {
            uint64_t raw = 0;
            std::memcpy(&raw, source->data() + at, laneBytes);
            const int64_t signedValue = static_cast<int64_t>(sextVal(raw, laneBits));
            // Two's-complement absolute value deliberately leaves INT_MIN as
            // INT_MIN, matching PABS rather than invoking signed overflow.
            const uint64_t absolute = signedValue < 0
                ? (~raw + 1U) & mask : raw & mask;
            std::memcpy(source->data() + at, &absolute, laneBytes);
        }
        return source;
    }
    if (op.op == POp::SIMD_SHUFFLE) {
        auto source = wideValue(op.in0);
        if (!source || !out) return std::nullopt;
        source->resize(size, 0);
        const int laneBits = op.aux & 0xff;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        if (!laneBytes || size % laneBytes) return std::nullopt;
        const unsigned mode = (op.aux >> 8) & 0x7f;
        // Mode 1 is PSHUFB: each 128-bit block is independently indexed and
        // selector bit 7 requests a zero byte.
        if (mode == 1) {
            auto selector = wideValue(op.in1);
            if (!selector) return std::nullopt;
            selector->resize(size, 0);
            std::vector<uint8_t> result(size, 0);
            for (size_t at = 0; at < size; ++at) {
                const size_t block = (at / 16) * 16;
                const uint8_t control = (*selector)[at];
                if ((control & 0x80) == 0)
                    result[at] = (*source)[block + (control & 0x0f)];
            }
            return result;
        }
        if (mode == 8 || mode == 9 || mode == 10) {
            std::vector<uint8_t> result(size, 0);
            for (size_t block = 0; block < size; block += 16) {
                if (mode == 10) { // MOVDDUP
                    std::memcpy(result.data() + block,
                                source->data() + block, 8);
                    std::memcpy(result.data() + block + 8,
                                source->data() + block, 8);
                } else {
                    const size_t first = mode == 8 ? 0 : 4;
                    const size_t second = mode == 8 ? 8 : 12;
                    for (size_t lane = 0; lane < 2; ++lane) {
                        std::memcpy(result.data() + block + lane * 4,
                                    source->data() + block + first, 4);
                        std::memcpy(result.data() + block + 8 + lane * 4,
                                    source->data() + block + second, 4);
                    }
                }
            }
            return result;
        }
        const auto immediate = varnodeValue(
            (mode == 5 || mode == 6 || mode == 7) ? op.in2 : op.in1);
        if (!immediate || size % 16) return std::nullopt;
        std::vector<uint8_t> result = *source;
        if (mode == 2 && laneBits == 32) { // PSHUFD
            for (size_t block = 0; block < size; block += 16)
                for (size_t lane = 0; lane < 4; ++lane) {
                    const size_t selected = (*immediate >> (lane * 2)) & 3;
                    std::memcpy(result.data() + block + lane * 4,
                                source->data() + block + selected * 4, 4);
                }
            return result;
        }
        if ((mode == 3 || mode == 4) && laneBits == 16) { // PSHUFLW/HW
            for (size_t block = 0; block < size; block += 16) {
                const size_t half = mode == 4 ? 8 : 0;
                for (size_t lane = 0; lane < 4; ++lane) {
                    const size_t selected = (*immediate >> (lane * 2)) & 3;
                    std::memcpy(result.data() + block + half + lane * 2,
                                source->data() + block + half + selected * 2, 2);
                }
            }
            return result;
        }
        auto second = wideValue(op.in1);
        if (!second) return std::nullopt;
        second->resize(size, 0);
        if (mode == 7) { // PALIGNR: (destination:source) >> imm8 bytes
            std::fill(result.begin(), result.end(), 0);
            const size_t shift = static_cast<size_t>(*immediate & 0xffU);
            for (size_t block = 0; block < size; block += 16) {
                uint8_t concatenated[32] = {};
                std::memcpy(concatenated, second->data() + block, 16);
                std::memcpy(concatenated + 16, source->data() + block, 16);
                if (shift < 32) {
                    const size_t available = std::min<size_t>(16, 32 - shift);
                    std::memcpy(result.data() + block,
                                concatenated + shift, available);
                }
            }
            return result;
        }
        if (mode == 5 && laneBits == 32) { // SHUFPS
            for (size_t block = 0; block < size; block += 16) {
                for (size_t lane = 0; lane < 2; ++lane) {
                    const size_t selected = (*immediate >> (lane * 2)) & 3;
                    std::memcpy(result.data() + block + lane * 4,
                                source->data() + block + selected * 4, 4);
                }
                for (size_t lane = 2; lane < 4; ++lane) {
                    const size_t selected = (*immediate >> (lane * 2)) & 3;
                    std::memcpy(result.data() + block + lane * 4,
                                second->data() + block + selected * 4, 4);
                }
            }
            return result;
        }
        if (mode == 6 && laneBits == 64) { // SHUFPD
            for (size_t block = 0, pair = 0; block < size;
                 block += 16, ++pair) {
                const size_t left = (*immediate >> (pair * 2)) & 1;
                const size_t right = (*immediate >> (pair * 2 + 1)) & 1;
                std::memcpy(result.data() + block,
                            source->data() + block + left * 8, 8);
                std::memcpy(result.data() + block + 8,
                            second->data() + block + right * 8, 8);
            }
            return result;
        }
        return std::nullopt;
    }
    if (op.op == POp::SIMD_SHIFT) {
        auto source = wideValue(op.in0);
        auto countValue = varnodeValue(op.in1);
        // Variable packed shifts use the low 64 bits of XMM/m128 as an
        // unmasked count. Counts at or above the lane width zero the lane,
        // except arithmetic right shifts which retain the sign.
        if (!countValue) {
            const auto countBytes = wideValue(op.in1);
            if (countBytes && !countBytes->empty()) {
                uint64_t low = 0;
                std::memcpy(&low, countBytes->data(),
                            std::min<size_t>(8, countBytes->size()));
                countValue = low;
            }
        }
        if (!source || !countValue || !out) return std::nullopt;
        source->resize(size, 0);
        const int laneBits = op.aux & 0xff;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        if (!laneBytes || laneBytes > 8 || size % laneBytes)
            return std::nullopt;
        const bool right = (op.aux & 0x0100) != 0;
        const bool arithmetic = (op.aux & 0x0200) != 0;
        const unsigned count = static_cast<unsigned>(*countValue);
        const uint64_t laneMask = laneBytes == 8
                                      ? ~0ULL : ((1ULL << laneBits) - 1);
        for (size_t at = 0; at < size; at += laneBytes) {
            uint64_t value = 0;
            std::memcpy(&value, source->data() + at, laneBytes);
            uint64_t result = 0;
            if (count < static_cast<unsigned>(laneBits)) {
                if (!right) result = (value << count) & laneMask;
                else if (arithmetic)
                    result = static_cast<uint64_t>(
                        static_cast<int64_t>(sextVal(value, laneBits)) >> count) &
                             laneMask;
                else result = value >> count;
            } else if (right && arithmetic &&
                       (value & (1ULL << (laneBits - 1)))) {
                result = laneMask;
            }
            std::memcpy(source->data() + at, &result, laneBytes);
        }
        return source;
    }
    if (op.op == POp::SIMD_EXTRACT) {
        auto source = wideValue(op.in0);
        const auto index = varnodeValue(op.in1);
        if (!source || !index || !out) return std::nullopt;
        const size_t laneBytes = static_cast<size_t>((op.aux & 0xff) / 8);
        const size_t lanes = source->size() / laneBytes;
        if (!lanes) return std::nullopt;
        const size_t at = (static_cast<size_t>(*index) % lanes) * laneBytes;
        if (!laneBytes || at > source->size() ||
            laneBytes > source->size() - at || size > laneBytes)
            return std::nullopt;
        return std::vector<uint8_t>(source->begin() + at,
                                    source->begin() + at + size);
    }
    if (op.op == POp::SIMD_INSERT) {
        auto base = wideValue(op.in0);
        auto lane = wideValue(op.in1);
        const auto index = varnodeValue(op.in2);
        if (!base || !lane || !index || !out) return std::nullopt;
        base->resize(size, 0);
        const size_t laneBytes = static_cast<size_t>((op.aux & 0xff) / 8);
        const size_t lanes = size / laneBytes;
        if (!lanes) return std::nullopt;
        const size_t at = (static_cast<size_t>(*index) % lanes) * laneBytes;
        if (!laneBytes || at > size || laneBytes > size - at ||
            lane->size() < laneBytes)
            return std::nullopt;
        std::memcpy(base->data() + at, lane->data(), laneBytes);
        return base;
    }
    if (op.op == POp::SIMD_BROADCAST) {
        auto lane = wideValue(op.in0);
        if (!lane || !out) return std::nullopt;
        const size_t laneBytes = static_cast<size_t>((op.aux & 0xff) / 8);
        if (!laneBytes || lane->size() < laneBytes || size % laneBytes)
            return std::nullopt;
        std::vector<uint8_t> result(size, 0);
        for (size_t at = 0; at < size; at += laneBytes)
            std::memcpy(result.data() + at, lane->data(), laneBytes);
        return result;
    }
    if (op.op == POp::SIMD_GATHER || op.op == POp::SIMD_SCATTER) {
        const auto base = varnodeValue(op.in0);
        auto indices = wideValue(op.in1);
        auto values = op.op == POp::SIMD_SCATTER ? wideValue(op.in2)
                                                  : wideValue(op.out);
        if (!base || !indices || !values) return std::nullopt;
        const int laneBits = op.aux & 0xff;
        const bool index64 = (op.aux & 0x0100) != 0;
        const unsigned scaleShift = (op.aux >> 9) & 3U;
        const unsigned maskIndex = (op.aux >> 11) & 7U;
        const bool zeroMasked = (op.aux & 0x4000) != 0;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        const size_t indexBytes = index64 ? 8 : 4;
        const size_t vectorBytes = op.op == POp::SIMD_SCATTER
                                       ? values->size() : size;
        if (!laneBytes || laneBytes > 8 || !indexBytes ||
            vectorBytes % laneBytes)
            return std::nullopt;
        values->resize(vectorBytes, 0);
        const size_t lanes = vectorBytes / laneBytes;
        if (indices->size() < lanes * indexBytes) return std::nullopt;
        uint64_t mask = maskIndex
            ? regs[8192 + static_cast<uint64_t>(maskIndex) * 8]
            : ~0ULL;
        for (size_t lane = 0; lane < lanes; ++lane) {
            if (((mask >> lane) & 1U) == 0) {
                if (op.op == POp::SIMD_GATHER && zeroMasked)
                    std::fill(values->begin() + lane * laneBytes,
                              values->begin() + (lane + 1) * laneBytes, 0);
                continue;
            }
            uint64_t rawIndex = 0;
            std::memcpy(&rawIndex, indices->data() + lane * indexBytes,
                        indexBytes);
            const int64_t signedIndex = index64
                ? static_cast<int64_t>(rawIndex)
                : static_cast<int64_t>(static_cast<int32_t>(rawIndex));
            const uint64_t address = *base +
                (static_cast<uint64_t>(signedIndex) << scaleShift);
            if (op.op == POp::SIMD_GATHER) {
                for (size_t byte = 0; byte < laneBytes; ++byte) {
                    const auto found = ram.find(address + byte);
                    if (found == ram.end()) return std::nullopt;
                    (*values)[lane * laneBytes + byte] = found->second;
                }
                mask &= ~(1ULL << lane);
            } else {
                for (size_t byte = 0; byte < laneBytes; ++byte)
                    ram[address + byte] = (*values)[lane * laneBytes + byte];
            }
        }
        if (op.op == POp::SIMD_GATHER && maskIndex)
            regs[8192 + static_cast<uint64_t>(maskIndex) * 8] = mask;
        return op.op == POp::SIMD_GATHER ? values : std::nullopt;
    }
    if (op.op == POp::SIMD_AVERAGE || op.op == POp::SIMD_MINMAX ||
        op.op == POp::SIMD_SAD) {
        auto left = wideValue(op.in0);
        auto right = wideValue(op.in1);
        if (!left || !right || !out) return std::nullopt;
        left->resize(size, 0); right->resize(size, 0);
        if (op.op == POp::SIMD_SAD) {
            if (size % 16) return std::nullopt;
            std::vector<uint8_t> result(size, 0);
            for (size_t block = 0; block < size; block += 16)
                for (size_t half = 0; half < 2; ++half) {
                    uint64_t sum = 0;
                    for (size_t byte = 0; byte < 8; ++byte) {
                        const size_t at = block + half * 8 + byte;
                        const int difference = static_cast<int>((*left)[at]) -
                                               static_cast<int>((*right)[at]);
                        sum += static_cast<uint64_t>(std::abs(difference));
                    }
                    std::memcpy(result.data() + block + half * 8, &sum, 8);
                }
            return result;
        }
        const int laneBits = op.aux & 0xff;
        const size_t laneBytes = static_cast<size_t>(laneBits / 8);
        if (!laneBytes || laneBytes > 8 || size % laneBytes)
            return std::nullopt;
        const uint64_t mask = laneBytes == 8 ? ~0ULL
                              : ((1ULL << laneBits) - 1);
        const bool signedValues = (op.aux & 0x0100U) != 0;
        const bool maximum = (op.aux & 0x0200U) != 0;
        for (size_t at = 0; at < size; at += laneBytes) {
            uint64_t x = 0, y = 0, result = 0;
            std::memcpy(&x, left->data() + at, laneBytes);
            std::memcpy(&y, right->data() + at, laneBytes);
            x &= mask; y &= mask;
            if (op.op == POp::SIMD_AVERAGE) {
                result = (x + y + 1U) >> 1;
            } else if (signedValues) {
                const int64_t sx = static_cast<int64_t>(sextVal(x, laneBits));
                const int64_t sy = static_cast<int64_t>(sextVal(y, laneBits));
                result = static_cast<uint64_t>(maximum ? std::max(sx, sy)
                                                        : std::min(sx, sy));
            } else {
                result = maximum ? std::max(x, y) : std::min(x, y);
            }
            result &= mask;
            std::memcpy(left->data() + at, &result, laneBytes);
        }
        return left;
    }
    if (op.op == POp::GF2P8_MUL) {
        auto left = wideValue(op.in0);
        auto right = wideValue(op.in1);
        if (!left || !right || !out) return std::nullopt;
        left->resize(size, 0);
        right->resize(size, 0);
        for (size_t byte = 0; byte < size; ++byte)
            (*left)[byte] = gf256Multiply((*left)[byte], (*right)[byte]);
        return left;
    }
    if (op.op == POp::GF2P8_AFFINE ||
        op.op == POp::GF2P8_AFFINE_INV) {
        auto source = wideValue(op.in0);
        auto matrix = wideValue(op.in1);
        const auto immediate = varnodeValue(op.in2);
        if (!source || !matrix || !immediate || !out || !size || size % 8)
            return std::nullopt;
        source->resize(size, 0);
        matrix->resize(size, 0);
        for (size_t byte = 0; byte < size; ++byte) {
            uint8_t input = (*source)[byte];
            if (op.op == POp::GF2P8_AFFINE_INV)
                input = gf256Inverse(input);
            const size_t matrixBase = (byte / 8) * 8;
            uint8_t transformed = static_cast<uint8_t>(*immediate);
            for (unsigned bit = 0; bit < 8; ++bit)
                transformed ^= static_cast<uint8_t>(
                    parity8(input & (*matrix)[matrixBase + 7 - bit]) << bit);
            (*source)[byte] = transformed;
        }
        return source;
    }
    if (op.op == POp::CARRYLESS_MULT) {
        auto left = wideValue(op.in0);
        auto right = wideValue(op.in1);
        const auto immediate = varnodeValue(op.in2);
        if (!left || !right || !immediate || !out || !size || size % 16)
            return std::nullopt;
        left->resize(size, 0);
        right->resize(size, 0);
        std::vector<uint8_t> result(size, 0);
        const size_t leftOffset = (*immediate & 1U) ? 8 : 0;
        const size_t rightOffset = (*immediate & 0x10U) ? 8 : 0;
        for (size_t lane = 0; lane < size; lane += 16) {
            uint64_t a = 0, b = 0, low = 0, high = 0;
            std::memcpy(&a, left->data() + lane + leftOffset, 8);
            std::memcpy(&b, right->data() + lane + rightOffset, 8);
            for (unsigned bit = 0; bit < 64; ++bit) {
                if (((b >> bit) & 1U) == 0) continue;
                low ^= a << bit;
                if (bit) high ^= a >> (64U - bit);
            }
            std::memcpy(result.data() + lane, &low, 8);
            std::memcpy(result.data() + lane + 8, &high, 8);
        }
        return result;
    }
    if (op.op == POp::SHA1_MSG1 || op.op == POp::SHA1_MSG2 ||
        op.op == POp::SHA1_NEXTE || op.op == POp::SHA1_RNDS4 ||
        op.op == POp::SHA256_MSG1 || op.op == POp::SHA256_MSG2 ||
        op.op == POp::SHA256_RNDS2) {
        auto first = wideValue(op.in0);
        auto second = wideValue(op.in1);
        if (!first || !second || !out || size != 16) return std::nullopt;
        first->resize(16, 0);
        second->resize(16, 0);
        std::vector<uint8_t> result(16, 0);
        if (op.op == POp::SHA1_MSG1) {
            writeDword(result, 3, readDword(*first, 3) ^ readDword(*first, 1));
            writeDword(result, 2, readDword(*first, 2) ^ readDword(*first, 0));
            writeDword(result, 1, readDword(*first, 1) ^ readDword(*second, 3));
            writeDword(result, 0, readDword(*first, 0) ^ readDword(*second, 2));
            return result;
        }
        if (op.op == POp::SHA1_MSG2) {
            const uint32_t w16 = rotateLeft32(readDword(*first, 3) ^
                                               readDword(*second, 2), 1);
            const uint32_t w17 = rotateLeft32(readDword(*first, 2) ^
                                               readDword(*second, 1), 1);
            const uint32_t w18 = rotateLeft32(readDword(*first, 1) ^
                                               readDword(*second, 0), 1);
            const uint32_t w19 = rotateLeft32(readDword(*first, 0) ^ w16, 1);
            writeDword(result, 3, w16); writeDword(result, 2, w17);
            writeDword(result, 1, w18); writeDword(result, 0, w19);
            return result;
        }
        if (op.op == POp::SHA1_NEXTE) {
            result = *second;
            writeDword(result, 3, rotateLeft32(readDword(*first, 3), 30) +
                                      readDword(*second, 3));
            return result;
        }
        if (op.op == POp::SHA1_RNDS4) {
            const auto immediate = varnodeValue(op.in2);
            if (!immediate) return std::nullopt;
            uint32_t a = readDword(*first, 3), b = readDword(*first, 2);
            uint32_t c = readDword(*first, 1), d = readDword(*first, 0);
            uint32_t e = 0;
            const unsigned mode = static_cast<unsigned>(*immediate) & 3U;
            const uint32_t constant = mode == 0 ? 0x5a827999U
                                    : mode == 1 ? 0x6ed9eba1U
                                    : mode == 2 ? 0x8f1bbcdcU : 0xca62c1d6U;
            for (unsigned round = 0; round < 4; ++round) {
                const uint32_t f = mode == 0 ? ((b & c) ^ (~b & d))
                                   : mode == 2 ? ((b & c) ^ (b & d) ^ (c & d))
                                               : (b ^ c ^ d);
                const uint32_t next = rotateLeft32(a, 5) + f + e + constant +
                                      readDword(*second, 3 - round);
                e = d; d = c; c = rotateLeft32(b, 30); b = a; a = next;
            }
            writeDword(result, 3, a); writeDword(result, 2, b);
            writeDword(result, 1, c); writeDword(result, 0, d);
            return result;
        }
        auto sigma0 = [](uint32_t x) {
            return rotateRight32(x, 7) ^ rotateRight32(x, 18) ^ (x >> 3);
        };
        auto sigma1 = [](uint32_t x) {
            return rotateRight32(x, 17) ^ rotateRight32(x, 19) ^ (x >> 10);
        };
        if (op.op == POp::SHA256_MSG1) {
            writeDword(result, 0, readDword(*first, 0) + sigma0(readDword(*first, 1)));
            writeDword(result, 1, readDword(*first, 1) + sigma0(readDword(*first, 2)));
            writeDword(result, 2, readDword(*first, 2) + sigma0(readDword(*first, 3)));
            writeDword(result, 3, readDword(*first, 3) + sigma0(readDword(*second, 0)));
            return result;
        }
        if (op.op == POp::SHA256_MSG2) {
            const uint32_t w16 = readDword(*first, 0) +
                                 sigma1(readDword(*second, 2));
            const uint32_t w17 = readDword(*first, 1) +
                                 sigma1(readDword(*second, 3));
            const uint32_t w18 = readDword(*first, 2) + sigma1(w16);
            const uint32_t w19 = readDword(*first, 3) + sigma1(w17);
            writeDword(result, 0, w16); writeDword(result, 1, w17);
            writeDword(result, 2, w18); writeDword(result, 3, w19);
            return result;
        }
        auto message = wideValue(op.in2); // implicit XMM0 for SHA256RNDS2
        if (!message) return std::nullopt;
        uint32_t a = readDword(*second, 3), b = readDword(*second, 2);
        uint32_t c = readDword(*first, 3), d = readDword(*first, 2);
        uint32_t e = readDword(*second, 1), f = readDword(*second, 0);
        uint32_t g = readDword(*first, 1), h = readDword(*first, 0);
        for (unsigned round = 0; round < 2; ++round) {
            const uint32_t big1 = rotateRight32(e, 6) ^ rotateRight32(e, 11) ^
                                  rotateRight32(e, 25);
            const uint32_t choose = (e & f) ^ (~e & g);
            const uint32_t t1 = h + big1 + choose + readDword(*message, round);
            const uint32_t big0 = rotateRight32(a, 2) ^ rotateRight32(a, 13) ^
                                  rotateRight32(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = big0 + majority;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        writeDword(result, 3, a); writeDword(result, 2, b);
        writeDword(result, 1, e); writeDword(result, 0, f);
        return result;
    }
    if (op.op == POp::AES_ENC || op.op == POp::AES_DEC ||
        op.op == POp::AES_IMC || op.op == POp::AES_KEYGEN) {
        auto state = wideValue(op.in0);
        if (!state || !out || !size || size % 16) return std::nullopt;
        state->resize(size, 0);
        if (op.op == POp::AES_KEYGEN) {
            const auto immediate = varnodeValue(op.in1);
            if (!immediate || size != 16) return std::nullopt;
            std::vector<uint8_t> result(16, 0);
            auto transformWord = [&](size_t sourceAt, size_t destinationAt,
                                     bool rotate) {
                uint8_t word[4] = {};
                for (size_t byte = 0; byte < 4; ++byte)
                    word[byte] = aesSbox((*state)[sourceAt + byte]);
                if (rotate) {
                    const uint8_t first = word[0];
                    word[0] = word[1]; word[1] = word[2];
                    word[2] = word[3]; word[3] = first;
                    word[0] ^= static_cast<uint8_t>(*immediate);
                }
                std::memcpy(result.data() + destinationAt, word, 4);
            };
            transformWord(4, 0, false);
            transformWord(4, 4, true);
            transformWord(12, 8, false);
            transformWord(12, 12, true);
            return result;
        }
        auto roundKey = wideValue(op.in1);
        if ((op.op == POp::AES_ENC || op.op == POp::AES_DEC) && !roundKey)
            return std::nullopt;
        if (roundKey) roundKey->resize(size, 0);
        const bool inverse = op.op == POp::AES_DEC || op.op == POp::AES_IMC;
        const bool lastRound = (op.aux & 1U) != 0;
        for (size_t lane = 0; lane < size; lane += 16) {
            if (op.op == POp::AES_IMC) {
                aesMixColumns(state->data() + lane, true);
                continue;
            }
            aesShiftSub(state->data() + lane, inverse);
            if (!lastRound) aesMixColumns(state->data() + lane, inverse);
            for (size_t byte = 0; byte < 16; ++byte)
                (*state)[lane + byte] ^= (*roundKey)[lane + byte];
        }
        return state;
    }
    if (op.op == POp::FLOAT_ROUND || op.op == POp::FLOAT_SIN ||
        op.op == POp::FLOAT_COS || op.op == POp::FLOAT_TAN ||
        op.op == POp::FLOAT_ATAN2 || op.op == POp::FLOAT_LOG2 ||
        op.op == POp::FLOAT_EXP2 || op.op == POp::FLOAT_REMAINDER ||
        op.op == POp::FLOAT_SCALE) {
        auto first = wideValue(op.in0);
        if (!first || !out || size < 10) return std::nullopt;
        first->resize(size, 0);
        std::vector<uint8_t> firstLane(first->begin(), first->begin() + 10);
        const auto decodedFirst = decodeFloatValue(firstLane, 80);
        if (!decodedFirst) return std::nullopt;
        long double result = *decodedFirst;
        auto secondValue = [&]() -> std::optional<long double> {
            const auto second = wideValue(op.in1);
            if (!second || second->size() < 10) return std::nullopt;
            return decodeFloatValue(
                std::vector<uint8_t>(second->begin(), second->begin() + 10), 80);
        };
        switch (op.op) {
        case POp::FLOAT_ROUND: {
            const auto control = varnodeValue(op.in1);
            if (!control) return std::nullopt;
            switch ((*control >> 10) & 3U) {
            case 0: result = std::nearbyint(result); break;
            case 1: result = std::floor(result); break;
            case 2: result = std::ceil(result); break;
            case 3: result = std::trunc(result); break;
            }
            break;
        }
        case POp::FLOAT_SIN: result = std::sin(result); break;
        case POp::FLOAT_COS: result = std::cos(result); break;
        case POp::FLOAT_TAN: result = std::tan(result); break;
        case POp::FLOAT_LOG2: result = std::log2(result); break;
        case POp::FLOAT_EXP2: result = std::exp2(result); break;
        case POp::FLOAT_ATAN2: {
            const auto second = secondValue();
            if (!second) return std::nullopt;
            result = std::atan2(result, *second);
            break;
        }
        case POp::FLOAT_REMAINDER: {
            const auto second = secondValue();
            if (!second) return std::nullopt;
            result = (op.aux & 0x0100U) ? std::fmod(result, *second)
                                        : std::remainder(result, *second);
            break;
        }
        case POp::FLOAT_SCALE: {
            const auto second = secondValue();
            if (!second) return std::nullopt;
            result *= std::exp2(std::trunc(*second));
            break;
        }
        default: return std::nullopt;
        }
        const uint16_t control = static_cast<uint16_t>(
            regValue(12416).value_or(0x037f));
        uint16_t raised = 0;
        if ((op.op == POp::FLOAT_SIN || op.op == POp::FLOAT_COS ||
             op.op == POp::FLOAT_TAN) && std::isinf(*decodedFirst))
            raised |= 1U << 0;
        if (op.op == POp::FLOAT_LOG2 && *decodedFirst < 0)
            raised |= 1U << 0;
        if (op.op == POp::FLOAT_LOG2 && *decodedFirst == 0)
            raised |= 1U << 2;
        if (std::isfinite(*decodedFirst) && std::isinf(result))
            raised |= 1U << 3;
        bool inexact = false;
        result = roundX87Precision(result, control, inexact);
        if (inexact) raised |= 1U << 5;
        if (result != 0 && std::fpclassify(result) == FP_SUBNORMAL)
            raised |= 1U << 4;
        if (raised) {
            uint16_t status = static_cast<uint16_t>(
                regValue(12418).value_or(0));
            status |= raised;
            if (raised & static_cast<uint16_t>(~control) & 0x3fU)
                status |= (1U << 7) | (1U << 15); // ES and B
            regs[12418] = status;
        }
        const auto encoded = encodeFloatValue(result, 80);
        std::copy(encoded.begin(), encoded.end(), first->begin());
        return first;
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
        if (floatBits != 32 && floatBits != 64 && floatBits != 80)
            return std::nullopt;
        const auto converted = encodeFloatValue(
            static_cast<long double>(signedValue), floatBits);
        std::copy(converted.begin(), converted.end(), result.begin());
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
        const auto sourceValue = decodeFloatValue(*input, sourceBits);
        if (!sourceValue || (destinationBits != 32 && destinationBits != 64 &&
                             destinationBits != 80))
            return std::nullopt;
        const auto converted = encodeFloatValue(*sourceValue, destinationBits);
        std::copy(converted.begin(), converted.end(), result.begin());
        return result;
    }
    auto a = wideValue(op.in0);
    auto b = wideValue(op.in1);
    if (!a) return std::nullopt;
    a->resize(size, 0);
    if (op.op == POp::COPY) return a;
    if (op.op == POp::INT_NOT) {
        for (uint8_t& byte : *a) byte = static_cast<uint8_t>(~byte);
        return a;
    }
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
    if ((laneBytes != 4 && laneBytes != 8 && laneBytes != 10) ||
        size % laneBytes)
        return std::nullopt;
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
        } else if (laneBytes == 8) {
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
        } else {
            std::vector<uint8_t> xBytes(source.begin() + at,
                                        source.begin() + at + laneBytes);
            const auto xValue = decodeFloatValue(xBytes, 80);
            if (!xValue) return std::nullopt;
            long double x = *xValue, y = 0, z = 0;
            if (b) {
                std::vector<uint8_t> yBytes(b->begin() + at,
                                            b->begin() + at + laneBytes);
                const auto yValue = decodeFloatValue(yBytes, 80);
                if (!yValue) return std::nullopt;
                y = *yValue;
            }
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
            const uint16_t control = static_cast<uint16_t>(
                regValue(12416).value_or(0x037f));
            uint16_t raised = 0;
            if ((op.op == POp::FLOAT_SQRT && x < 0) ||
                (op.op == POp::FLOAT_DIV &&
                 ((x == 0 && y == 0) ||
                  (std::isinf(x) && std::isinf(y)))))
                raised |= 1U << 0;
            else if (op.op == POp::FLOAT_DIV && y == 0 &&
                     std::isfinite(x) && x != 0)
                raised |= 1U << 2;
            if (std::isfinite(x) && (unary || std::isfinite(y)) &&
                std::isinf(z))
                raised |= 1U << 3;
            bool inexact = false;
            z = roundX87Precision(z, control, inexact);
            if (inexact) raised |= 1U << 5;
            if (z != 0 && std::fpclassify(z) == FP_SUBNORMAL)
                raised |= 1U << 4;
            if (raised) {
                uint16_t status = static_cast<uint16_t>(
                    regValue(12418).value_or(0));
                status |= raised;
                if (raised & static_cast<uint16_t>(~control) & 0x3fU)
                    status |= (1U << 7) | (1U << 15);
                regs[12418] = status;
            }
            const auto encoded = encodeFloatValue(z, 80);
            std::copy(encoded.begin(), encoded.end(), a->begin() + at);
        }
    }
    return a;
}

} // namespace centrifuge
