// centrifuge - a Ghidra reimplementation in C++17
// loader_pe.cpp - PE32/PE32+ loader with export-table parsing
#include "centrifuge/loader.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace centrifuge {
namespace {

#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;   // 'MZ'
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};
struct CoffHeader {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};
struct SecHeader {
    char name[8];
    uint32_t virtualSize, virtualAddress, sizeOfRawData, pointerToRawData;
    uint32_t pointerToRelocations, pointerToLinenumbers;
    uint16_t numberOfRelocations, numberOfLinenumbers;
    uint32_t characteristics;
};
#pragma pack(pop)

constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x14c;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM = 0x1c0;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
constexpr uint16_t IMAGE_FILE_MACHINE_RISCV64 = 0x5064;

constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
bool rangeInFile(uint64_t off, uint64_t size, size_t fileSize) {
    return off <= fileSize && size <= static_cast<uint64_t>(fileSize) - off;
}

bool addOk(uint64_t a, uint64_t b, uint64_t& out) {
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

template <typename T>
bool rd(const std::vector<uint8_t>& d, size_t off, T& out) {
    if (off > d.size() || sizeof(T) > d.size() - off) return false;
    std::memcpy(&out, d.data() + off, sizeof(T));
    return true;
}

uint16_t rd16(const std::vector<uint8_t>& d, size_t off) {
    uint16_t v = 0;
    rd(d, off, v);
    return v;
}
uint32_t rd32(const std::vector<uint8_t>& d, size_t off) {
    uint32_t v = 0;
    rd(d, off, v);
    return v;
}
uint64_t rd64(const std::vector<uint8_t>& d, size_t off) {
    uint64_t v = 0;
    rd(d, off, v);
    return v;
}

struct PeSections {
    std::vector<SecHeader> secs;
    std::optional<uint32_t> rvaToOffset(uint32_t rva) const {
        for (const auto& s : secs) {
            if (rva < s.virtualAddress) continue;
            const uint64_t delta = static_cast<uint64_t>(rva) - s.virtualAddress;
            if (delta >= s.sizeOfRawData) continue;
            const uint64_t off = static_cast<uint64_t>(s.pointerToRawData) + delta;
            if (off <= std::numeric_limits<uint32_t>::max())
                return static_cast<uint32_t>(off);
        }
        return std::nullopt;
    }
};

std::string cstrAt(const std::vector<uint8_t>& d, size_t off, size_t maxLen) {
    std::string s;
    if (off >= d.size()) return s;
    const size_t available = d.size() - off;
    for (size_t i = 0; i < maxLen && i < available; ++i) {
        if (d[off + i] == 0) break;
        s.push_back(static_cast<char>(d[off + i]));
    }
    return s;
}

std::string sectionName(const char (&name)[8]) {
    size_t n = 0;
    while (n < sizeof(name) && name[n] != '\0') ++n;
    return std::string(name, n);
}

std::optional<Program> loadPeImpl(const std::vector<uint8_t>& d,
                                  const std::string& path,
                                  uint64_t maxMappedBytes,
                                  std::string& err) {
    DosHeader dos;
    if (!rd(d, 0, dos) || dos.e_magic != 0x5A4D) {
        err = "not a PE file (bad MZ header)";
        return std::nullopt;
    }
    const size_t peOff = dos.e_lfanew;
    uint32_t sig = 0;
    if (!rd(d, peOff, sig) || sig != 0x00004550) { // "PE\0\0"
        err = "bad PE signature";
        return std::nullopt;
    }
    CoffHeader coff;
    if (!rd(d, peOff + 4, coff)) {
        err = "truncated COFF header";
        return std::nullopt;
    }
    if (coff.numberOfSections == 0) {
        err = "PE has no sections";
        return std::nullopt;
    }
    const size_t optOff = peOff + 24;
    if (!rangeInFile(optOff, coff.sizeOfOptionalHeader, d.size())) {
        err = "truncated optional header";
        return std::nullopt;
    }
    const uint16_t magic = rd16(d, optOff);
    const bool is64 = (magic == 0x20B);
    if (magic != 0x10B && magic != 0x20B) {
        err = "unsupported optional-header magic";
        return std::nullopt;
    }
    const size_t minOptionalSize = is64 ? 112 : 96;
    if (coff.sizeOfOptionalHeader < minOptionalSize) {
        err = "optional header too small";
        return std::nullopt;
    }

    Program p;
    p.path = path;
    p.format = is64 ? "PE32+" : "PE32";
    switch (coff.machine) {
    case IMAGE_FILE_MACHINE_I386:  p.arch = "x86"; break;
    case IMAGE_FILE_MACHINE_AMD64: p.arch = "x86-64"; break;
    case IMAGE_FILE_MACHINE_ARM:   p.arch = "arm"; break;
    case IMAGE_FILE_MACHINE_ARM64: p.arch = "aarch64"; break;
    case IMAGE_FILE_MACHINE_RISCV64: p.arch = "riscv64"; break;
    default: p.arch = "unknown"; break;
    }

    const uint32_t entryRva = rd32(d, optOff + 16);
    const uint32_t sizeOfImage = rd32(d, optOff + 56);
    const uint32_t numRvaSizes = rd32(d, optOff + (is64 ? 108 : 92));
    const size_t dataDirOff = optOff + (is64 ? 112 : 96);
    if (is64) {
        p.imageBase = rd64(d, optOff + 24);
    } else {
        p.imageBase = rd32(d, optOff + 28);
    }
    if (sizeOfImage == 0) {
        err = "PE has zero SizeOfImage";
        return std::nullopt;
    }
    if (!addOk(p.imageBase, entryRva, p.entryPoint)) {
        err = "entry point address overflow";
        return std::nullopt;
    }

    // ---- section table ----
    const size_t secTabOff = optOff + coff.sizeOfOptionalHeader;
    const uint64_t secTableSize =
        static_cast<uint64_t>(coff.numberOfSections) * sizeof(SecHeader);
    if (!rangeInFile(secTabOff, secTableSize, d.size())) {
        err = "truncated section table";
        return std::nullopt;
    }
    PeSections ps;
    for (uint16_t i = 0; i < coff.numberOfSections; ++i) {
        SecHeader s;
        if (!rd(d, secTabOff + static_cast<size_t>(i) * sizeof(SecHeader), s)) {
            err = "truncated section table";
            return std::nullopt;
        }
        ps.secs.push_back(s);
    }

    // ---- memory image: one block per section (zero-padded to virtual size) ----
    uint64_t mappedTotal = 0;
    for (const auto& s : ps.secs) {
        const std::string name = sectionName(s.name);
        const uint32_t memSz = std::max(s.virtualSize, s.sizeOfRawData);
        if (memSz == 0) continue;
        if (memSz > maxMappedBytes || mappedTotal > maxMappedBytes - memSz ||
            !rangeInFile(s.pointerToRawData, s.sizeOfRawData, d.size())) {
            err = "invalid section range";
            return std::nullopt;
        }
        mappedTotal += memSz;
        uint64_t sectionAddr = 0;
        if (!addOk(p.imageBase, s.virtualAddress, sectionAddr)) {
            err = "section address overflow";
            return std::nullopt;
        }
        std::vector<uint8_t> bytes(memSz, 0);
        if (s.sizeOfRawData > 0)
            std::memcpy(bytes.data(), d.data() + s.pointerToRawData,
                        s.sizeOfRawData);
        int perm = 0;
        if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
            perm |= static_cast<int>(Perm::X);
        if (s.characteristics & IMAGE_SCN_MEM_WRITE)
            perm |= static_cast<int>(Perm::W);
        if (s.characteristics & IMAGE_SCN_MEM_READ)
            perm |= static_cast<int>(Perm::R);
        else if (s.characteristics & IMAGE_SCN_CNT_CODE)
            perm |= static_cast<int>(Perm::R);
        if (!p.memory.addBlock(name, sectionAddr, std::move(bytes), perm)) {
            err = "overlapping or invalid section range";
            return std::nullopt;
        }
        p.sections.push_back(Section{
            name.empty() ? "(unnamed)" : name, sectionAddr,
            memSz, s.pointerToRawData, s.sizeOfRawData, perm});
    }

    // ---- x64 exception directory (.pdata / IMAGE_RUNTIME_FUNCTION_ENTRY) ----
    // Each entry maps a protected code range to UNWIND_INFO.  EHANDLER and
    // UHANDLER records carry a language-specific handler RVA after the
    // aligned unwind-code array.
    if (is64 && numRvaSizes > 3 &&
        coff.sizeOfOptionalHeader >= (is64 ? 144u : 128u)) {
        const uint32_t excRva = rd32(d, dataDirOff + 3 * 8);
        const uint32_t excSize = rd32(d, dataDirOff + 3 * 8 + 4);
        const auto excOff = ps.rvaToOffset(excRva);
        if (excRva && excSize && excOff) {
            if (excSize % 12 != 0 || !rangeInFile(*excOff, excSize, d.size())) {
                err = "invalid PE exception directory";
                return std::nullopt;
            }
            const uint32_t count = excSize / 12;
            for (uint32_t i = 0; i < count; ++i) {
                const size_t entry = *excOff + static_cast<size_t>(i) * 12;
                const uint32_t beginRva = rd32(d, entry);
                const uint32_t endRva = rd32(d, entry + 4);
                const uint32_t unwindRva = rd32(d, entry + 8);
                if (!beginRva || endRva <= beginRva || !unwindRva) continue;
                ExceptionRegion region;
                region.kind = ExceptionRegion::WINDOWS_UNWIND;
                if (!addOk(p.imageBase, beginRva, region.start) ||
                    !addOk(p.imageBase, endRva, region.end) ||
                    !addOk(p.imageBase, unwindRva, region.unwindInfo)) {
                    err = "PE exception address overflow";
                    return std::nullopt;
                }
                const auto unwindOff = ps.rvaToOffset(unwindRva);
                if (unwindOff && rangeInFile(*unwindOff, 4, d.size())) {
                    const uint8_t flags = d[*unwindOff] >> 3;
                    const uint8_t codeCount = d[*unwindOff + 2];
                    const size_t slots = (static_cast<size_t>(codeCount) + 1) & ~size_t{1};
                    const size_t handlerOff = *unwindOff + 4 + slots * 2;
                    if ((flags & 0x3) && rangeInFile(handlerOff, 4, d.size())) {
                        const uint32_t handlerRva = rd32(d, handlerOff);
                        if (handlerRva &&
                            !addOk(p.imageBase, handlerRva, region.handler)) {
                            err = "PE exception handler overflow";
                            return std::nullopt;
                        }
                        if (rangeInFile(handlerOff + 4, 1, d.size()))
                            region.languageData = p.imageBase + unwindRva +
                                                  (handlerOff + 4 - *unwindOff);
                    }
                }
                p.exceptionRegions.push_back(region);
            }
        }
    }

    // ---- export table ----
    if (numRvaSizes > 0) {
        const size_t requiredOptionalSize = is64 ? 120 : 104;
        if (coff.sizeOfOptionalHeader < requiredOptionalSize) {
            err = "truncated export data directory";
            return std::nullopt;
        }
        const uint32_t expRva = rd32(d, dataDirOff); // directory[0]
        if (expRva != 0) {
            const auto expOff = ps.rvaToOffset(expRva);
            if (expOff) {
                if (!rangeInFile(*expOff, 40, d.size())) {
                    err = "truncated export directory";
                    return std::nullopt;
                }
                const uint32_t nFuncs = rd32(d, *expOff + 20);
                const uint32_t nNames = rd32(d, *expOff + 24);
                const uint32_t funcsRva = rd32(d, *expOff + 28);
                const uint32_t namesRva = rd32(d, *expOff + 32);
                const uint32_t ordsRva = rd32(d, *expOff + 36);
                const auto funcsOff = ps.rvaToOffset(funcsRva);
                const auto namesOff = ps.rvaToOffset(namesRva);
                const auto ordsOff = ps.rvaToOffset(ordsRva);
                const uint32_t n = std::min(nFuncs, nNames);
                if (funcsOff && namesOff && ordsOff && n > 0) {
                    if (!rangeInFile(*funcsOff,
                                     static_cast<uint64_t>(nFuncs) * 4,
                                     d.size()) ||
                        !rangeInFile(*namesOff,
                                     static_cast<uint64_t>(nNames) * 4,
                                     d.size()) ||
                        !rangeInFile(*ordsOff,
                                     static_cast<uint64_t>(nNames) * 2,
                                     d.size())) {
                        err = "export table out of file";
                        return std::nullopt;
                    }
                    for (uint32_t i = 0; i < n; ++i) {
                        const uint16_t ord = rd16(d, *ordsOff + 2 * i);
                        if (ord >= nFuncs) continue;
                        const uint32_t fnRva = rd32(d, *funcsOff + 4 * ord);
                        const uint32_t nameRva = rd32(d, *namesOff + 4 * i);
                        const auto nameOff = ps.rvaToOffset(nameRva);
                        if (!nameOff || fnRva == 0) continue;
                        Symbol sym;
                        sym.name = cstrAt(d, *nameOff, 512);
                        if (!addOk(p.imageBase, fnRva, sym.addr)) {
                            err = "export address overflow";
                            return std::nullopt;
                        }
                        sym.isFunction = true;
                        sym.isExported = true;
                        p.symbols.push_back(std::move(sym));
                    }
                }
            }
        }
    }

    // entry point as a pseudo-symbol
    if (p.entryPoint != 0) {
        Symbol e;
        e.name = "entry";
        e.addr = p.entryPoint;
        e.isFunction = true;
        p.symbols.push_back(std::move(e));
    }

    return p;
}

} // namespace

std::optional<Program> loadPe(const std::vector<uint8_t>& data,
                              const std::string& path,
                              uint64_t maxMappedBytes, std::string& err) {
    return loadPeImpl(data, path, maxMappedBytes, err);
}

} // namespace centrifuge
