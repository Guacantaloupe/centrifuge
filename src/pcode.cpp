// ghra - a Ghidra reimplementation in C++17
// pcode.cpp - p-code names + interpreter
#include "ghra/pcode.hpp"

#include <cstdio>

namespace ghra {

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
    case POp::BOOL_NEGATE: return "BOOL_NEGATE";
    case POp::BOOL_XOR: return "BOOL_XOR";
    case POp::BOOL_AND: return "BOOL_AND";
    case POp::BOOL_OR: return "BOOL_OR";
    case POp::PIECE: return "PIECE";
    case POp::SUBPIECE: return "SUBPIECE";
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

} // namespace

void PcodeEvaluator::run() {
    vals_.clear();
    lastBranch_.reset();
    branchTaken_ = false;
    for (const auto& op : insn_.ops) {
        std::optional<uint64_t> r = evalOp(op);
        if (op.out != 0) vals_[op.out] = r;
    }
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

    switch (op.op) {
    case POp::COPY: return in(op.in0);

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
        return (a && b) ? std::optional<uint64_t>(*a == *b) : std::nullopt;
    }
    case POp::INT_NOTEQUAL: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(*a != *b) : std::nullopt;
    }
    case POp::INT_LESS: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(*a < *b) : std::nullopt;
    }
    case POp::INT_SLESS: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const int sz = dst() ? dst() * 8 : 64;
        return std::optional<uint64_t>(
            sextVal(*a, sz) < sextVal(*b, sz));
    }
    case POp::INT_LESSEQUAL: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(*a <= *b) : std::nullopt;
    }
    case POp::INT_SLESSEQUAL: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const int sz = dst() ? dst() * 8 : 64;
        return std::optional<uint64_t>(
            sextVal(*a, sz) <= sextVal(*b, sz));
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
        uint64_t r = ~*a;
        if (dst()) r &= (dst() * 8 >= 64) ? ~0ULL
                                          : ((1ULL << (dst() * 8)) - 1);
        return r;
    }
    case POp::INT_XOR: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(*a ^ *b) : std::nullopt;
    }
    case POp::INT_AND: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(*a & *b) : std::nullopt;
    }
    case POp::INT_OR: {
        auto a = in(op.in0), b = in(op.in1);
        return (a && b) ? std::optional<uint64_t>(*a | *b) : std::nullopt;
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
        return (a && b) ? std::optional<uint64_t>(*b < 64 ? (*a >> *b) : 0)
                        : std::nullopt;
    }
    case POp::INT_SRIGHT: {
        auto a = in(op.in0), b = in(op.in1);
        if (!a || !b) return std::nullopt;
        const Varnode* vs = insn_.find(op.in0);
        const int bits = (vs ? vs->size : 8) * 8;
        if (*b >= 64) return 0;
        const int64_t s = static_cast<int64_t>(sextVal(*a, bits));
        return std::optional<uint64_t>(static_cast<uint64_t>(s >> *b));
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
        return std::optional<uint64_t>(static_cast<uint64_t>(x % y));
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
        return (*a << ((vb ? vb->size : 8) * 8)) | *b;
    }
    case POp::SUBPIECE: {
        auto a = in(op.in0);
        if (!a) return std::nullopt;
        const Varnode* vs = insn_.find(op.in0);
        const int sz = vs ? vs->size : 8;
        uint64_t r = 0;
        for (int i = 0; i < sz; ++i)
            r |= ((*a >> (8 * i)) & 0xFF) << (8 * i);
        return r & ((1ULL << (sz * 8)) - 1);
    }

    case POp::UNIMPLEMENTED:
        return std::nullopt;
    }
    return std::nullopt;
}

} // namespace ghra
