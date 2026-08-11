// centrifuge - a Ghidra reimplementation in C++17
// decompile.hpp - minimal C decompiler (v0.4-lite)
//
// Reconstructs register-level expressions from p-code and emits C with
// if/return structuring. No stack-frame analysis yet (that is v0.5) - the
// output is register-based and best on leaf functions.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "centrifuge/ir.hpp"
#include "centrifuge/sleigh.hpp"

namespace centrifuge {

// Decompile the function starting at `start` (until RET/undecodable/`end`).
// `nameOf` resolves call-target addresses to function names ("" = indirect).
std::string decompile(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end,
    const std::function<std::string(uint64_t)>& nameOf = nullptr,
    const std::function<std::optional<FunctionSignature>(uint64_t)>& signatureOf =
        nullptr,
    const std::string& architecture = "riscv64",
    bool useRecoveredRuntime = false);

// Emits a complete C-like function with the recovered declaration and ABI
// register aliases.  Direct calls use propagated callee signatures.
std::string decompileTyped(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end, const std::string& architecture, const std::string& functionName,
    const FunctionSignature& signature,
    const std::function<std::string(uint64_t)>& nameOf = nullptr,
    const std::function<std::optional<FunctionSignature>(uint64_t)>& signatureOf =
        nullptr,
    bool useRecoveredRuntime = false);

} // namespace centrifuge
