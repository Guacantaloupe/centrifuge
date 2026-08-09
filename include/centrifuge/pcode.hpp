// centrifuge - a Ghidra reimplementation in C++17
// pcode.hpp - p-code intermediate representation (Ghidra's decompiler IR)
//
// Every instruction decodes to a straight-line list of p-code ops over
// varnodes. This is the substrate for the Sleigh-style spec engine (v0.3),
// the future decompiler (v0.4+), and a small interpreter used for validation.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "centrifuge/disasm.hpp" // Insn

namespace centrifuge {

enum class POp : uint8_t {
    COPY,
    LOAD,
    STORE,
    BRANCH,
    CBRANCH,
    BRANCHIND,
    CALL,
    CALLIND,
    RETURN,
    INT_EQUAL,
    INT_NOTEQUAL,
    INT_LESS,
    INT_SLESS,
    INT_LESSEQUAL,
    INT_SLESSEQUAL,
    INT_ZEXT,
    INT_SEXT,
    INT_ADD,
    INT_SUB,
    INT_NEGATE,
    INT_XOR,
    INT_AND,
    INT_OR,
    INT_LEFT,
    INT_RIGHT,
    INT_SRIGHT,
    INT_MULT,
    INT_DIV,
    INT_SDIV,
    INT_REM,
    INT_SREM,
    INT_CARRY,
    INT_SCARRY,
    INT_SBORROW,
    INT_PARITY,
    INT_POPCOUNT,
    INT_COUNT_LEADING_ZERO,
    INT_COUNT_TRAILING_ZERO,
    INT_MULT_OVERFLOW,
    INT_SMULT_OVERFLOW,
    FLOAT_EQUAL,
    FLOAT_NOTEQUAL,
    FLOAT_LESS,
    FLOAT_LESSEQUAL,
    FLOAT_NAN,
    FLOAT_ADD,
    FLOAT_SUB,
    FLOAT_MULT,
    FLOAT_DIV,
    FLOAT_NEG,
    FLOAT_ABS,
    FLOAT_SQRT,
    FLOAT_MIN,
    FLOAT_MAX,
    // Conversion metadata is carried in PcodeOp::aux.  INT2FLOAT stores the
    // destination IEEE lane width, FLOAT2INT stores the source lane width and
    // bit 15 selects truncation, and FLOAT2FLOAT stores source/destination
    // widths in the low/high byte respectively.
    FLOAT_INT2FLOAT,
    FLOAT_FLOAT2INT,
    FLOAT_FLOAT2FLOAT,
    BOOL_NEGATE,
    BOOL_XOR,
    BOOL_AND,
    BOOL_OR,
    PIECE,
    SUBPIECE,
    SELECT,
    UNIMPLEMENTED,
};

const char* pOpName(POp p);

struct Varnode {
    uint64_t id = 0;
    enum Kind { REGISTER, CONST, UNIQUE, RAM } kind = CONST;
    uint64_t offset = 0; // reg offset / const value / unique id / ram address
    int size = 0;        // bytes
    std::string name;    // register name / temp name

    bool isConst() const { return kind == CONST; }
};

struct PcodeOp {
    POp op = POp::UNIMPLEMENTED;
    uint64_t out = 0; // varnode id, 0 = no output
    uint64_t in0 = 0, in1 = 0, in2 = 0;
    uint16_t aux = 0; // operation-specific metadata (e.g. SIMD lane width)
};

// p-code translation of a single machine instruction
struct PcodeInsn {
    uint64_t addr = 0;
    uint64_t nextAddr = 0;
    std::string text; // disassembly text
    int size = 0;
    Insn::Kind kind = Insn::OTHER;
    uint64_t target = 0;
    bool targetKnown = false;

    std::vector<PcodeOp> ops;
    std::map<uint64_t, Varnode> varnodes; // id -> varnode
    std::map<std::string, uint64_t> named; // operand name -> varnode id

    const Varnode* find(uint64_t id) const {
        auto it = varnodes.find(id);
        return it == varnodes.end() ? nullptr : &it->second;
    }
    std::string varnodeName(uint64_t id) const;
};

// Straightforward p-code interpreter. Registers/ram not provided are
// "unknown"; arithmetic on unknown yields unknown. Used both for semantic
// validation (concrete register values) and branch-target folding.
class PcodeEvaluator {
public:
    // Own the instruction so constructing an evaluator from a temporary
    // disassembly result cannot leave a dangling reference.
    explicit PcodeEvaluator(const PcodeInsn& insn) : insn_(insn) {}

    std::map<uint64_t, uint64_t> regs; // register offset -> value
    std::map<uint64_t, std::vector<uint8_t>> wideRegs; // SIMD registers
    std::map<uint64_t, uint8_t> ram;   // ram address -> byte

    void run();
    std::optional<uint64_t> regValue(uint64_t offset) const;
    std::optional<uint64_t> varnodeValue(uint64_t id) const;
    std::optional<std::vector<uint8_t>> wideValue(uint64_t id) const;
    std::optional<uint64_t> lastBranchTarget() const { return lastBranch_; }
    bool branchTaken() const { return branchTaken_; }

private:
    PcodeInsn insn_;
    std::map<uint64_t, std::optional<uint64_t>> vals_;
    std::map<uint64_t, std::optional<std::vector<uint8_t>>> wideVals_;
    std::optional<uint64_t> lastBranch_;
    bool branchTaken_ = false;
    std::optional<uint64_t> evalOp(const PcodeOp& op);
    std::optional<std::vector<uint8_t>> evalWideOp(const PcodeOp& op);
};

} // namespace centrifuge
