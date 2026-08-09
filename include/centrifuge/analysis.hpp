// centrifuge - a Ghidra reimplementation in C++17
// analysis.hpp - program analysis passes (function discovery, ...)
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "centrifuge/disasm.hpp"
#include "centrifuge/loader.hpp"

namespace centrifuge {

struct Function {
    std::string name;
    uint64_t addr = 0;
    uint64_t size = 0;
    enum Src { SYMBOL, EXPORT, ENTRY, SCAN } src = SCAN;
};

// Function discovery:
//   1. seed with symbol-table functions, PE exports, and the entry point;
//   2. recursive-descent scan from each seed (follow direct calls/jumps),
//      promoting direct call targets to new function starts;
//   3. sizes = distance to next function start (or containing block end).
// `disasm` may be null; then only symbol-derived functions are returned.
// Heuristic: indirect calls and conditional-branch targets are not followed,
// so hand-written asm with unusual CFG may under-report. Good enough for v0.1.
std::vector<Function> findFunctions(const Program& prog, Disassembler* disasm);

} // namespace centrifuge
