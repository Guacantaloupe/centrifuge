// ghra - a Ghidra reimplementation in C++17
// loader_pe.cpp - PE32/PE32+ loader with export-table parsing
#include "ghra/loader.hpp"

#include <algorithm>
#include <cstring>

namespace ghra {
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

template <typename T>
bool rd(const std::vector<uint8_t>& d, size_t off, T& out) {
    if (off + sizeof(T) > d.size()) return false;
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
            const uint32_t memSz = std::max(s.virtualSize, s.sizeOfRawData);
            if (rva >= s.virtualAddress && rva < s.virtualAddress + memSz)
                return s.pointerToRawData + (rva - s.virtualAddress);
        }
        return std::nullopt;
    }
};

std::string cstrAt(const std::vector<uint8_t>& d, size_t off, size_t maxLen) {
    std::string s;
    for (size_t i = 0; i < maxLen && off + i < d.size(); ++i) {
        if (d[off + i] == 0) break;
        s.push_back(static_cast<char>(d[off + i]));
    }
    return s;
}

std::optional<Program> loadPeImpl(const std::vector<uint8_t>& d,
                                  const std::string& path, std::string& err) {
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
    const uint16_t magic = rd16(d, optOff);
    const bool is64 = (magic == 0x20B);
    if (magic != 0x10B && magic != 0x20B) {
        err = "unsupported optional-header magic";
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
    const uint32_t numRvaSizes = rd32(d, optOff + 108);
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
    p.entryPoint = p.imageBase + entryRva;

    // ---- section table ----
    const size_t secTabOff = optOff + coff.sizeOfOptionalHeader;
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
    for (const auto& s : ps.secs) {
        const uint32_t memSz = std::max(s.virtualSize, s.sizeOfRawData);
        if (memSz == 0) continue;
        std::vector<uint8_t> bytes(memSz, 0);
        if (s.sizeOfRawData > 0 && s.pointerToRawData < d.size()) {
            const size_t n = std::min<uint32_t>(
                s.sizeOfRawData, static_cast<uint32_t>(d.size() - s.pointerToRawData));
            std::memcpy(bytes.data(), d.data() + s.pointerToRawData, n);
        }
        int perm = 0;
        if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
            perm |= static_cast<int>(Perm::X);
        if (s.characteristics & IMAGE_SCN_MEM_WRITE)
            perm |= static_cast<int>(Perm::W);
        if (s.characteristics & IMAGE_SCN_MEM_READ)
            perm |= static_cast<int>(Perm::R);
        else if (s.characteristics & IMAGE_SCN_CNT_CODE)
            perm |= static_cast<int>(Perm::R);
        p.memory.addBlock(s.name, p.imageBase + s.virtualAddress,
                          std::move(bytes), perm);
        p.sections.push_back(Section{
            s.name[0] ? s.name : "(unnamed)", p.imageBase + s.virtualAddress,
            memSz, s.pointerToRawData, s.sizeOfRawData, perm});
    }

    // ---- export table ----
    if (numRvaSizes > 0) {
        const uint32_t expRva = rd32(d, dataDirOff); // directory[0]
        if (expRva != 0) {
            const auto expOff = ps.rvaToOffset(expRva);
            if (expOff) {
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
                    for (uint32_t i = 0; i < n; ++i) {
                        const uint16_t ord = rd16(d, *ordsOff + 2 * i);
                        if (ord >= nFuncs) continue;
                        const uint32_t fnRva = rd32(d, *funcsOff + 4 * ord);
                        const uint32_t nameRva = rd32(d, *namesOff + 4 * i);
                        const auto nameOff = ps.rvaToOffset(nameRva);
                        if (!nameOff || fnRva == 0) continue;
                        Symbol sym;
                        sym.name = cstrAt(d, *nameOff, 512);
                        sym.addr = p.imageBase + fnRva;
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
                              const std::string& path, std::string& err) {
    return loadPeImpl(data, path, err);
}

} // namespace ghra
