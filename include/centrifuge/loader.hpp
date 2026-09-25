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

// A PE import-address-table binding.  Keeping both the lookup and IAT
// addresses lets later passes distinguish the symbolic API from the mutable
// loader slot used by indirect calls.
struct ImportSymbol {
    std::string library;
    std::string name;
    uint16_t hint = 0;
    uint16_t ordinal = 0;
    uint64_t lookupAddress = 0;
    uint64_t iatAddress = 0;
    // Synthetic stub address this import is bound to in the memory image
    // (0 when unbound).  The stub is a single `ret` in the mapped
    // "iat_stubs" block so indirect calls through the slot resolve to a
    // stable, named target for symbolic exploration and decompilation.
    uint64_t boundAddress = 0;
    bool byOrdinal = false;
    bool delayed = false;
};

// An initialized or zero-extended non-executable image region.  Its bytes
// remain available through Program::memory; this record preserves the file
// extent and permissions needed to reproduce global storage in a source
// project.
struct DataRegion {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    uint64_t initializedSize = 0;
    int perm = 0;
};

// Leaf of a PE resource directory.  Numeric and named identifiers are kept
// separately so custom resource types survive a round trip without inventing
// names or losing stable integer IDs.
struct ResourceEntry {
    uint32_t typeId = 0;
    uint32_t nameId = 0;
    uint32_t languageId = 0;
    std::string typeName;
    std::string name;
    uint64_t dataAddress = 0;
    uint32_t size = 0;
    uint32_t codePage = 0;
};

// PE thread-local-storage directory.  The raw template is already present in
// Program::memory; these addresses preserve the loader contract needed to
// materialize one private copy per host thread and to run process-attach TLS
// callbacks before the recovered entry point.
struct ThreadLocalStorage {
    uint64_t rawDataStart = 0;
    uint64_t rawDataEnd = 0;
    uint64_t addressOfIndex = 0;
    uint64_t addressOfCallbacks = 0;
    uint32_t zeroFillSize = 0;
    uint32_t characteristics = 0;
    std::vector<uint64_t> callbacks;
};

struct ExceptionRegion {
    enum Kind { WINDOWS_UNWIND, DWARF_CFI } kind = WINDOWS_UNWIND;
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t unwindInfo = 0;
    // Windows UNW_FLAG_CHAININFO links a secondary RUNTIME_FUNCTION range
    // back to another range of the same logical function.
    uint64_t chainedStart = 0;
    uint64_t chainedEnd = 0;
    uint64_t chainedUnwindInfo = 0;
    uint64_t handler = 0;
    uint64_t languageData = 0;
    struct Handler {
        uint64_t start = 0;
        uint64_t end = 0;
        uint64_t landingPad = 0;
        int64_t action = 0;
    };
    std::vector<Handler> handlers;
    ExceptionRegion() = default;
    ExceptionRegion(Kind regionKind, uint64_t begin, uint64_t finish,
                    uint64_t unwind, uint64_t personality,
                    uint64_t languageSpecificData)
        : kind(regionKind), start(begin), end(finish), unwindInfo(unwind),
          handler(personality), languageData(languageSpecificData) {}
};

struct Program {
    std::string path;
    std::string format; // "ELF64" | "ELF32" | "PE32+" | "PE32"
    std::string arch;   // "x86-64" | "x86" | "aarch64" | ...
    uint64_t imageBase = 0; // 0 for ELF (position-independent layout)
    uint64_t entryPoint = 0;
    // PE-only metadata (0 when not applicable / unspecified).
    uint16_t peSubsystem = 0;       // optional-header Subsystem field
    uint16_t peCharacteristics = 0; // COFF Characteristics field
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<std::string> importedLibraries;
    std::vector<ImportSymbol> imports;
    std::vector<DataRegion> dataRegions;
    std::vector<ResourceEntry> resources;
    std::optional<ThreadLocalStorage> tls;
    std::vector<ExceptionRegion> exceptionRegions;
    MemoryImage memory;
};

// True when the PE targets the native subsystem (IMAGE_SUBSYSTEM_NATIVE, 1) —
// i.e. a Windows kernel driver / KMDF-style image whose entry point is
// DriverEntry rather than a user-mode CRT startup routine.
inline bool isKernelDriver(const Program& p) {
    return p.peSubsystem == 1;
}

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
