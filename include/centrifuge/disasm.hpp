// centrifuge - a Ghidra reimplementation in C++17
// disasm.hpp - disassembler abstraction (the role Sleigh plays in Ghidra)
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "centrifuge/memory.hpp"

namespace centrifuge {

struct Insn {
    enum Kind { OTHER, CALL, RET, JMP, JCC, NOP };

    uint64_t addr = 0;
    std::vector<uint8_t> bytes;
    std::string text; // "mov rax, qword ptr [rip + 0x1234]"
    size_t size = 0;
    Kind kind = OTHER;
    uint64_t target = 0; // resolved branch/call target
    bool targetKnown = false;
};

class Disassembler {
public:
    virtual ~Disassembler() = default;

    // Disassemble exactly one instruction at addr. On success fills `out`
    // including size/kind/target; returns false on undecodable bytes or
    // unreadable memory.
    virtual bool disasmOne(const MemoryImage& mem, uint64_t addr, Insn& out) = 0;

    virtual std::string backendName() const = 0;
};

// Best available backend for the given architecture name ("x86-64", "x86",
// "aarch64", "arm", "mips", "ppc64", "riscv64", ...). Never returns null;
// falls back to a raw "opcode listing" backend when nothing supports the arch.
std::unique_ptr<Disassembler> makeDisassembler(const std::string& arch);

} // namespace centrifuge
