// centrifuge - calling-convention recovery (Phase 5 of the Native Source
// Recovery Backend).  Recovers Win64/SystemV calling-convention facts from
// the SSA IR and the p-code CFG:
//
//   - stack arguments: reads of [rsp + 0x28 + n*8] at callee entry
//   - variadic: dynamic (indexed) stack-argument access, e.g. printf-style
//     argument walking
//   - hidden sret: the first integer argument doubles as the return buffer
//     pointer (stores through rcx, return value == rcx)
//
// The Machine Semantic Backend remains the correctness oracle; this pass only
// annotates FunctionSignature so native output can name parameters, emit
// variadic declarations and keep sret buffers out of the visible ABI.
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/ir.hpp"

namespace centrifuge {

struct CallConventionFacts {
    // Callee reads arguments from the ABI stack area ([rsp+0x28..] on Win64).
    bool readsStackArguments = false;
    // Stack-argument access through a dynamic index (rsp + reg*8 + K), the
    // signature of printf-style variadic argument walking.
    bool indexedStackAccess = false;
    // The function returns the value of its first integer argument register.
    bool returnsPointerArgument = false;
    // The function stores through its first integer argument register.
    bool writesThroughFirstArg = false;
    // Final verdicts (derived from the flags above).
    bool variadic = false;
    bool hiddenSret = false;
    // {entry-relative offset, width} of every stack-argument slot read.
    std::vector<std::pair<int64_t, int>> stackSlots;
    // Number of ABI register arguments that are live at entry.
    size_t fixedRegisterArguments = 0;
};

// Analyze one function's calling convention from its SSA IR and p-code CFG.
CallConventionFacts recoverCallConvention(const FunctionIR& ir,
                                          const CfgBuilder& cfg,
                                          const std::string& architecture);

// Apply recovered facts to a signature (variadic flag, sret parameter,
// stack-argument slot ordering).  Conservative: only strengthens what the
// SSA-based signature inference already produced.
void applyCallConvention(const CallConventionFacts& facts,
                         FunctionSignature& signature,
                         const std::string& architecture);

} // namespace centrifuge
