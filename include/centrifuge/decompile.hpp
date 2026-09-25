// centrifuge - a Ghidra reimplementation in C++17
// decompile.hpp - minimal C decompiler (v0.4-lite)
//
// Reconstructs register-level expressions from p-code and emits C with
// if/return structuring. No stack-frame analysis yet (that is v0.5) - the
// output is register-based and best on leaf functions.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "centrifuge/ir.hpp"
#include "centrifuge/sleigh.hpp"
#include "centrifuge/stack_recovery.hpp"
#include "centrifuge/global_recovery.hpp"

namespace centrifuge {

// Recovered struct-member accessors, keyed by (parameter register pcode
// offset, byte displacement).  The value is the member name on the
// parameter's recovered struct type plus the member width in bits, so the
// emitter can rewrite *(T *)(base + K) into base->member when the width
// matches.
using FieldAccessorMap =
    std::map<std::pair<uint64_t, int64_t>, std::pair<std::string, int>>;

// WS6 symbolic-assisted decompilation: indirect call/jump sites whose
// targets the symbolic exploration engine resolved, keyed by instruction
// address.  A single-target call site devirtualizes to a direct named
// call; a multi-target jump site is switch-shaped evidence.
struct SymIndirectSiteInfo {
    bool isCall = false;            // true = CALLIND, false = BRANCHIND
    std::vector<uint64_t> targets;  // concrete targets observed, sorted
};
using SymIndirectSites = std::map<uint64_t, SymIndirectSiteInfo>;

// Symbolic-assisted unreachable-branch elimination (see symbolic.hpp
// BranchCoverage).  `outcomes` maps a branch instruction address to the
// bitmask of directions symbolic execution observed (bit0 = fall-through,
// bit1 = target).  A branch whose bitmask is exactly one bit had its other
// edge never executed: the emitter drops the dead arm and annotates the
// fold.  `visitedPcs` lets the emitter mark blocks no explored state ever
// reached.  Both are under-approximations, so `complete` gates on the
// exploration run having finished without budget exhaustion.
// Symbolic value-range evidence for one conditional branch address (see
// symbolic.hpp CondRangeInfo): the interval the symbolic engine
// structurally propagated for the condition's operand(s), merged over the
// explored evaluations.  Quoted as an annotation at the emitted
// conditional on complete runs only.
struct SymCondRangeInfo {
    uint64_t lo = 0, hi = 0;
    uint64_t rhsLo = 0, rhsHi = 0;
    uint64_t evaluations = 0;
    bool isCmp = false;
};

struct SymBranchCoverage {
    const std::map<uint64_t, unsigned>* outcomes = nullptr;
    const std::set<uint64_t>* visitedPcs = nullptr;
    const std::map<uint64_t, SymCondRangeInfo>* condRanges = nullptr;
    bool complete = false;
};

// Cross-function return-value summaries (see symbolic.hpp
// CallReturnSummary): one entry per explored call site, recording what the
// callee's return register actually held across every explored return.
// The emitter annotates the call site with the observed constant or range.
// Under-approximation like the coverage above, so it is only passed on a
// complete exploration run.
struct SymCallSummaryInfo {
    uint64_t callAddr = 0;
    uint64_t target = 0;
    uint64_t returns = 0;
    bool alwaysConst = false;
    uint64_t constValue = 0;
    uint64_t lo = 0, hi = 0;
};

// Decompile the function starting at `start` (until RET/undecodable/`end`).
// `nameOf` resolves call-target addresses to function names ("" = indirect).
// `stackModel` (optional) enables the Native Source Recovery Backend:
// provably-stable stack slots promoted by StackFrameAnalysis are emitted as
// local variables instead of raw memory expressions.
std::string decompile(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end,
    const std::function<std::string(uint64_t)>& nameOf = nullptr,
    const std::function<std::optional<FunctionSignature>(uint64_t)>& signatureOf =
        nullptr,
    const std::string& architecture = "riscv64",
    bool useRecoveredRuntime = false,
    const StackFrameModel* stackModel = nullptr,
    const GlobalObjectRecovery* globals = nullptr,
    const std::function<bool(uint64_t)>& guardSlotOf = nullptr,
    const std::string& entryName = "",
    const FunctionSignature* callerSignature = nullptr,
    const FieldAccessorMap* fieldAccessors = nullptr,
    const std::map<uint64_t, DataType>* callResultTypes = nullptr,
    const std::map<uint64_t, CppVirtualCallSite>* virtualCallSites = nullptr,
    const SymIndirectSites* symIndirectSites = nullptr,
    const SymBranchCoverage* symCoverage = nullptr,
    const std::vector<JumpTable>* jumpTables = nullptr,
    const std::vector<SymCallSummaryInfo>* symCallSummaries = nullptr);

// Emits a complete C-like function with the recovered declaration and ABI
// register aliases.  Direct calls use propagated callee signatures.
// `stackModel` (optional) enables native local-variable declaration from
// the stack frame model instead of text scanning.
std::string decompileTyped(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end, const std::string& architecture, const std::string& functionName,
    const FunctionSignature& signature,
    const std::function<std::string(uint64_t)>& nameOf = nullptr,
    const std::function<std::optional<FunctionSignature>(uint64_t)>& signatureOf =
        nullptr,
    bool useRecoveredRuntime = false,
    const StackFrameModel* stackModel = nullptr,
    const GlobalObjectRecovery* globals = nullptr,
    const std::function<bool(uint64_t)>& guardSlotOf = nullptr,
    const FieldAccessorMap* fieldAccessors = nullptr,
    const std::map<uint64_t, DataType>* callResultTypes = nullptr,
    const std::map<uint64_t, CppVirtualCallSite>* virtualCallSites =
        nullptr,
    const SymIndirectSites* symIndirectSites = nullptr,
    const SymBranchCoverage* symCoverage = nullptr,
    const std::vector<JumpTable>* jumpTables = nullptr,
    const std::vector<SymCallSummaryInfo>* symCallSummaries = nullptr);

} // namespace centrifuge
