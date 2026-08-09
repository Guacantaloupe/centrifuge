// centrifuge - a Ghidra reimplementation in C++17
// loader.hpp - file-format front ends (ELF, PE, ...) producing a Program
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "centrifuge/memory.hpp"

namespace centrifuge {

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

struct ExceptionRegion {
    enum Kind { WINDOWS_UNWIND, DWARF_CFI } kind = WINDOWS_UNWIND;
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t unwindInfo = 0;
    uint64_t handler = 0;
    uint64_t languageData = 0;
};

struct Program {
    std::string path;
    std::string format; // "ELF64" | "ELF32" | "PE32+" | "PE32"
    std::string arch;   // "x86-64" | "x86" | "aarch64" | ...
    uint64_t imageBase = 0; // 0 for ELF (position-independent layout)
    uint64_t entryPoint = 0;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<ExceptionRegion> exceptionRegions;
    MemoryImage memory;
};

struct LoadOptions {
    // Maximum cumulative number of bytes materialized in the memory image.
    // Callers processing untrusted inputs can lower this to limit allocations.
    uint64_t maxMappedBytes = 1ULL << 30;
};

// Load any supported binary. Returns nullopt and sets `error` on failure.
std::optional<Program> loadFile(const std::string& path, std::string& error);

// Load a supported binary directly from memory. `virtualPath` is retained in
// Program::path for diagnostics and does not need to exist on disk.
std::optional<Program> loadData(const uint8_t* data, size_t size,
                                const std::string& virtualPath,
                                std::string& error);
std::optional<Program> loadData(const uint8_t* data, size_t size,
                                const std::string& virtualPath,
                                const LoadOptions& options,
                                std::string& error);
std::optional<Program> loadData(const std::vector<uint8_t>& data,
                                const std::string& virtualPath,
                                std::string& error);
std::optional<Program> loadData(const std::vector<uint8_t>& data,
                                const std::string& virtualPath,
                                const LoadOptions& options,
                                std::string& error);

} // namespace centrifuge
