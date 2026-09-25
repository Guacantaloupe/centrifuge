// centrifuge - a Ghidra reimplementation in C++17
// symbolic.hpp - a small angr-style symbolic execution engine
//
// Executes the program's p-code with symbolic input and derives concrete
// inputs that drive execution to a target address.  The engine is
// deliberately bounded: BFS path exploration with per-state step and
// per-address revisit limits, and a propagator-based bit-vector solver
// (interval narrowing over the input-byte domains, verified by concrete
// evaluation).  Unsupported operations prune the path with a recorded
// reason; irreducible paths are never guessed.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include "centrifuge/loader.hpp"
#include "centrifuge/sleigh.hpp"

namespace centrifuge {

struct ReachOptions {
    uint64_t targetAddress = 0;  // address a reaching input must execute
    uint64_t startAddress = 0;   // 0 = program entry point
    uint64_t maxStates = 4096;   // queued states before exploration gives up
    uint64_t maxStepsPerState = 100000;
    uint64_t loopBound = 32;     // per-state visits of one pc before pruning
    // Model stdin reads as `length` symbolic bytes: every read/fgets/gets
    // from fd 0 delivers this many fresh symbolic bytes to the buffer.
    bool symbolicStdin = false;
    uint64_t stdinLength = 16;
    // Additional memory ranges whose bytes start as symbolic inputs.
    std::vector<std::pair<uint64_t, uint64_t>> symbolicMemory; // addr, len
    // When non-empty, run concretely with these input bytes (verification
    // replay): every input() leaf returns the given byte, branches never
    // fork, and the result reports whether the target was hit.
    std::vector<uint8_t> concreteInput;
    // Diagnostic execution trace of the winning path (pc per step).
    bool trace = false;
};

struct ReachResult {
    bool reached = false;
    std::string reason;  // "found" / why exploration failed
    // Concrete stdin payload satisfying every path constraint, or the
    // symbolic-memory seed when no stdin model was requested.
    std::vector<uint8_t> input;
    // Index into `input` where stdin-modeled bytes begin (skipping the
    // argv[1] seed and --sym-mem ranges).
    uint32_t stdinOffset = 0;
    uint64_t steps = 0;
    uint64_t statesExplored = 0;
    uint64_t statesPruned = 0;
    std::vector<uint64_t> winningPath;  // pc trace when trace enabled
};

// Symbolically execute `program` (via `engine`, already spec-loaded) from
// the entry point (or options.startAddress) and search for an input that
// makes execution reach options.targetAddress.
ReachResult reachTarget(const SleighEngine& engine, const Program& program,
                        const ReachOptions& options);

// One indirect call/jump instruction observed during exploration, together
// with the concrete targets symbolic execution resolved for it.  A site with
// several targets is the fingerprint of a switch over a jump table or a
// vtable dispatch; a single target is usually an import thunk or an
// indirectly-referenced helper.
struct IndirectSite {
    uint64_t addr = 0;              // address of the CALLIND/BRANCHIND insn
    bool isCall = false;            // true = CALLIND, false = BRANCHIND
    std::vector<uint64_t> targets;  // concrete targets, sorted ascending
};

// Branch-direction coverage harvested during exploration, keyed by the
// machine address of the branching instruction.  `outcomes` maps a branch
// address to a bitmask of the successors symbolic execution actually
// executed from it: bit0 = fall-through, bit1 = jump target.  A value of
// exactly one bit means every explored execution agreed on a single
// direction.  `visitedPcs` is the set of instruction addresses any explored
// state executed.  Coverage is an under-approximation of real behavior:
// unobserved directions/blocks are dead code evidence, not proof, and are
// only safe to act on when the run completed without budget exhaustion.
struct CondRangeInfo {
    uint64_t lo = 0, hi = 0;        // merged unsigned interval of the
                                    // condition's left operand (or of the
                                    // condition itself when not a compare)
    uint64_t rhsLo = 0, rhsHi = 0;  // right-operand interval when isCmp
    uint64_t evaluations = 0;       // explored evaluations merged
    bool isCmp = false;             // condition was a comparison node
};

struct BranchCoverage {
    std::map<uint64_t, unsigned> outcomes;  // branch addr -> bit0 fall, bit1 taken
    std::set<uint64_t> visitedPcs;
    // Symbolic value range propagation: per conditional-branch address, the
    // interval of the branch condition's operand(s) structurally propagated
    // through the symbolic expression (input bytes start as [0, 255] each),
    // merged over every explored evaluation at that branch.  An
    // under-approximation like `outcomes` - sound to quote only on a
    // complete run.
    std::map<uint64_t, CondRangeInfo> condRanges;
};

// Cross-function return-value summary for one call site, harvested while
// exploring.  Every time a state returns from the callee reached by the
// call instruction at `callAddr`, the architectural return register (rax /
// x0) is observed and merged into the summary.  `alwaysConst` means every
// observed return carried the same concrete value, in which case
// `constValue` is it; `lo`/`hi` bound the observed values unsigned.
// Summaries are an under-approximation: they describe the explored paths
// only and are only trustworthy when the run completed without budget
// exhaustion.
struct CallReturnSummary {
    uint64_t callAddr = 0;    // address of the CALL/CALLIND instruction
    uint64_t target = 0;      // concrete callee observed at this site
    uint64_t returns = 0;     // number of returns merged into the summary
    bool alwaysConst = false;
    uint64_t constValue = 0;
    uint64_t lo = 0, hi = 0;  // unsigned range over observed returns
};

struct IndirectExploreResult {
    std::vector<IndirectSite> sites;
    std::vector<CallReturnSummary> returnSummaries;
    uint64_t statesExplored = 0;
    uint64_t statesPruned = 0;
    std::string reason;
    // Branch-direction / pc coverage observed while exploring.  Only
    // meaningful when `reason` reports a complete exploration; on budget
    // exhaustion the absence of a direction may mean "not explored", not
    // "unreachable".
    BranchCoverage coverage;
};

// Bounded symbolic exploration from the entry point (or options.startAddress)
// that runs to completion and records every indirect call/branch instruction
// whose target resolved to a concrete address on at least one explored path,
// along with the full set of targets observed per site.  options.targetAddress
// is ignored; all budgets (maxStates, maxStepsPerState, loopBound,
// symbolicStdin, symbolicMemory) behave exactly as in reachTarget.
IndirectExploreResult exploreIndirectTargets(const SleighEngine& engine,
                                             const Program& program,
                                             const ReachOptions& options);

} // namespace centrifuge
