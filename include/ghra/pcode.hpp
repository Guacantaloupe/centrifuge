// ghra - a Ghidra reimplementation in C++17
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

#include "ghra/disasm.hpp" // Insn

namespace ghra {

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
    BOOL_NEGATE,
    BOOL_XOR,
    BOOL_AND,
    BOOL_OR,
    PIECE,
    SUBPIECE,
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
    explicit PcodeEvaluator(const PcodeInsn& insn) : insn_(insn) {}

    std::map<uint64_t, uint64_t> regs; // register offset -> value
    std::map<uint64_t, uint8_t> ram;   // ram address -> byte

    void run();
    std::optional<uint64_t> regValue(uint64_t offset) const;
    std::optional<uint64_t> varnodeValue(uint64_t id) const;
    std::optional<uint64_t> lastBranchTarget() const { return lastBranch_; }
    bool branchTaken() const { return branchTaken_; }

private:
    const PcodeInsn& insn_;
    std::map<uint64_t, std::optional<uint64_t>> vals_;
    std::optional<uint64_t> lastBranch_;
    bool branchTaken_ = false;
    std::optional<uint64_t> evalOp(const PcodeOp& op);
};

} // namespace ghra
