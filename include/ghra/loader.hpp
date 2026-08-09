// ghra - a Ghidra reimplementation in C++17
// loader.hpp - file-format front ends (ELF, PE, ...) producing a Program
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ghra/memory.hpp"

namespace ghra {

struct Section {
    std::string name;
    uint64_t addr = 0;      // virtual address
    uint64_t size = 0;      // size in memory (may include zero-filled tail)
    uint64_t fileOffset = 0;
    uint64_t fileSize = 0;  // bytes present in the file
    int perm = 0;           // OR of Perm values
};

struct Symbol {
    std::string name;
    uint64_t addr = 0;
    uint64_t size = 0;
    bool isFunction = false;
    bool isExported = false; // came from dynsym / PE export table
};

struct Program {
    std::string path;
    std::string format; // "ELF64" | "ELF32" | "PE32+" | "PE32"
    std::string arch;   // "x86-64" | "x86" | "aarch64" | ...
    uint64_t imageBase = 0; // 0 for ELF (position-independent layout)
    uint64_t entryPoint = 0;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    MemoryImage memory;
};

// Load any supported binary. Returns nullopt and sets `error` on failure.
std::optional<Program> loadFile(const std::string& path, std::string& error);

} // namespace ghra
