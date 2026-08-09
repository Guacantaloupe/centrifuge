// ghra - a Ghidra reimplementation in C++17
// decompile.hpp - minimal C decompiler (v0.4-lite)
//
// Reconstructs register-level expressions from p-code and emits C with
// if/return structuring. No stack-frame analysis yet (that is v0.5) - the
// output is register-based and best on leaf functions.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "ghra/sleigh.hpp"

namespace ghra {

// Decompile the function starting at `start` (until RET/undecodable/`end`).
std::string decompile(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end);

} // namespace ghra
