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
#include <string>
#include <utility>

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
    const std::map<uint64_t, CppVirtualCallSite>* virtualCallSites =
        nullptr);

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
        nullptr);

} // namespace centrifuge
