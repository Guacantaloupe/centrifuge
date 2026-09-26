// centrifuge - a Ghidra reimplementation in C++17
// loader_pe.cpp - PE32/PE32+ loader with imports, exports and resources
#include "centrifuge/loader.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <set>
#include <sstream>

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

std::string utf16ResourceString(const std::vector<uint8_t>& data, size_t off) {
    if (!rangeInFile(off, 2, data.size())) return {};
    const uint16_t length = rd16(data, off);
    if (length > 4096 || !rangeInFile(off + 2,
                                      static_cast<uint64_t>(length) * 2,
                                      data.size()))
        return {};
    std::string result;
    for (uint16_t index = 0; index < length; ++index) {
        const uint16_t code = rd16(data, off + 2 + index * 2);
        if (code < 0x80) {
            result.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            result.push_back(static_cast<char>(0xc0 | (code >> 6)));
            result.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        } else {
            result.push_back(static_cast<char>(0xe0 | (code >> 12)));
            result.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
            result.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        }
    }
    return result;
}

std::string standardResourceType(uint32_t id) {
    static const char* names[] = {
        "", "CURSOR", "BITMAP", "ICON", "MENU", "DIALOG", "STRING",
        "FONTDIR", "FONT", "ACCELERATOR", "RCDATA", "MESSAGETABLE",
        "GROUP_CURSOR", "", "GROUP_ICON", "", "VERSION", "DLGINCLUDE",
        "", "PLUGPLAY", "VXD", "ANICURSOR", "ANIICON", "HTML", "MANIFEST"
    };
    return id < sizeof(names) / sizeof(names[0]) ? names[id] : std::string();
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
    const uint32_t sizeOfHeaders = rd32(d, optOff + 60);
    p.peSubsystem = rd16(d, optOff + 68);
    p.peCharacteristics = coff.characteristics;
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

    // ---- memory image: PE headers plus one block per section ----
    // The mapped headers are observable at ImageBase and are consulted by the
    // MSVC CRT, RTTI helpers, resource lookup, and exception machinery.
    if (!sizeOfHeaders || sizeOfHeaders > d.size() ||
        sizeOfHeaders > maxMappedBytes) {
        err = "invalid PE SizeOfHeaders";
        return std::nullopt;
    }
    std::vector<uint8_t> headerBytes(sizeOfHeaders);
    std::memcpy(headerBytes.data(), d.data(), sizeOfHeaders);
    if (!p.memory.addBlock("headers", p.imageBase, std::move(headerBytes),
                           static_cast<int>(Perm::R))) {
        err = "invalid PE header mapping";
        return std::nullopt;
    }
    uint64_t mappedTotal = sizeOfHeaders;
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
        if ((perm & static_cast<int>(Perm::X)) == 0) {
            p.dataRegions.push_back(DataRegion{
                name.empty() ? "(unnamed)" : name, sectionAddr, memSz,
                s.sizeOfRawData, perm});
        }
    }

    const size_t directoryBytes = coff.sizeOfOptionalHeader >
            dataDirOff - optOff
        ? coff.sizeOfOptionalHeader - (dataDirOff - optOff) : 0;
    const size_t availableDirectories = std::min<size_t>(
        numRvaSizes, directoryBytes / 8);
    auto directory = [&](size_t index) {
        std::pair<uint32_t, uint32_t> result{};
        if (index < availableDirectories) {
            result.first = rd32(d, dataDirOff + index * 8);
            result.second = rd32(d, dataDirOff + index * 8 + 4);
        }
        return result;
    };
    const unsigned thunkWidth = is64 ? 8U : 4U;

    // ---- thread-local storage template and loader callbacks ----
    // IMAGE_TLS_DIRECTORY stores virtual addresses (not RVAs).  Keeping the
    // exact template range is essential for MSVC's per-thread static-local
    // epoch at GS:[0x58] -> TLS slot; a zero-filled stand-in changes guard
    // ordering and can skip constructors entirely.
    const auto tlsDirectory = directory(9);
    if (tlsDirectory.first) {
        const size_t structureSize = is64 ? 40U : 24U;
        const auto tlsOff = ps.rvaToOffset(tlsDirectory.first);
        if (!tlsOff || tlsDirectory.second < structureSize ||
            !rangeInFile(*tlsOff, structureSize, d.size())) {
            err = "invalid PE TLS directory";
            return std::nullopt;
        }
        ThreadLocalStorage tls;
        if (is64) {
            tls.rawDataStart = rd64(d, *tlsOff);
            tls.rawDataEnd = rd64(d, *tlsOff + 8);
            tls.addressOfIndex = rd64(d, *tlsOff + 16);
            tls.addressOfCallbacks = rd64(d, *tlsOff + 24);
            tls.zeroFillSize = rd32(d, *tlsOff + 32);
            tls.characteristics = rd32(d, *tlsOff + 36);
        } else {
            tls.rawDataStart = rd32(d, *tlsOff);
            tls.rawDataEnd = rd32(d, *tlsOff + 4);
            tls.addressOfIndex = rd32(d, *tlsOff + 8);
            tls.addressOfCallbacks = rd32(d, *tlsOff + 12);
            tls.zeroFillSize = rd32(d, *tlsOff + 16);
            tls.characteristics = rd32(d, *tlsOff + 20);
        }
        if (tls.rawDataEnd < tls.rawDataStart ||
            tls.rawDataEnd - tls.rawDataStart > maxMappedBytes ||
            static_cast<uint64_t>(tls.zeroFillSize) > maxMappedBytes -
                (tls.rawDataEnd - tls.rawDataStart)) {
            err = "invalid PE TLS template range";
            return std::nullopt;
        }
        const uint64_t rawSize = tls.rawDataEnd - tls.rawDataStart;
        uint8_t boundary = 0;
        uint32_t indexValue = 0;
        const MemoryBlock* rawBlock = rawSize
            ? p.memory.blockAt(tls.rawDataStart) : nullptr;
        if ((rawSize &&
             (!rawBlock || tls.rawDataStart > rawBlock->end() ||
              rawSize > rawBlock->end() - tls.rawDataStart ||
              !p.memory.read(tls.rawDataStart, &boundary, 1) ||
              !p.memory.read(tls.rawDataEnd - 1, &boundary, 1))) ||
            !tls.addressOfIndex ||
            !p.memory.read(tls.addressOfIndex, &indexValue,
                           sizeof(indexValue))) {
            err = "PE TLS storage is outside the mapped image";
            return std::nullopt;
        }
        if (tls.addressOfCallbacks) {
            bool terminated = false;
            for (size_t index = 0; index < 4096; ++index) {
                const uint64_t byteOffset =
                    static_cast<uint64_t>(index) * thunkWidth;
                if (tls.addressOfCallbacks >
                    std::numeric_limits<uint64_t>::max() - byteOffset) {
                    err = "PE TLS callback address overflow";
                    return std::nullopt;
                }
                uint64_t callback = 0;
                if (is64) {
                    if (!p.memory.read(tls.addressOfCallbacks + byteOffset,
                                       &callback, sizeof(callback)))
                        break;
                } else {
                    uint32_t callback32 = 0;
                    if (!p.memory.read(tls.addressOfCallbacks + byteOffset,
                                       &callback32, sizeof(callback32)))
                        break;
                    callback = callback32;
                }
                if (!callback) {
                    terminated = true;
                    break;
                }
                if (!p.memory.isExecutable(callback)) {
                    err = "PE TLS callback is not executable";
                    return std::nullopt;
                }
                tls.callbacks.push_back(callback);
            }
            if (!terminated) {
                err = "unterminated PE TLS callback array";
                return std::nullopt;
            }
        }
        p.tls = std::move(tls);
    }

    // ---- import and delay-import tables ----
    auto addLibrary = [&](const std::string& library) {
        if (std::find(p.importedLibraries.begin(), p.importedLibraries.end(),
                      library) == p.importedLibraries.end())
            p.importedLibraries.push_back(library);
    };
    auto parseThunks = [&](const std::string& library, uint32_t lookupRva,
                           uint32_t iatRva, bool delayed) {
        const auto lookupOff = ps.rvaToOffset(lookupRva);
        const auto iatOff = ps.rvaToOffset(iatRva);
        if (!lookupOff || !iatOff) return false;
        bool terminated = false;
        const uint64_t ordinalMask = is64 ? (1ULL << 63) : (1ULL << 31);
        for (size_t index = 0; index < 1'000'000; ++index) {
            const uint64_t byteIndex = static_cast<uint64_t>(index) * thunkWidth;
            if (!rangeInFile(static_cast<uint64_t>(*lookupOff) + byteIndex,
                             thunkWidth, d.size()) ||
                !rangeInFile(static_cast<uint64_t>(*iatOff) + byteIndex,
                             thunkWidth, d.size()))
                return false;
            const uint64_t thunk = is64
                ? rd64(d, static_cast<size_t>(*lookupOff + byteIndex))
                : rd32(d, static_cast<size_t>(*lookupOff + byteIndex));
            if (!thunk) {
                terminated = true;
                break;
            }
            ImportSymbol imported;
            imported.library = library;
            imported.delayed = delayed;
            imported.byOrdinal = (thunk & ordinalMask) != 0;
            if (imported.byOrdinal) {
                imported.ordinal = static_cast<uint16_t>(thunk & 0xffffU);
            } else {
                if (thunk > std::numeric_limits<uint32_t>::max()) return false;
                const auto nameOff = ps.rvaToOffset(static_cast<uint32_t>(thunk));
                if (!nameOff || !rangeInFile(*nameOff, 3, d.size())) return false;
                imported.hint = rd16(d, *nameOff);
                imported.name = cstrAt(d, *nameOff + 2, 4096);
                if (imported.name.empty()) return false;
            }
            const uint64_t lookupSlotRva =
                static_cast<uint64_t>(lookupRva) + byteIndex;
            const uint64_t iatSlotRva = static_cast<uint64_t>(iatRva) + byteIndex;
            if (!addOk(p.imageBase, lookupSlotRva, imported.lookupAddress) ||
                !addOk(p.imageBase, iatSlotRva, imported.iatAddress))
                return false;
            Symbol slot;
            slot.name = library + "!" + (imported.byOrdinal
                ? ("#" + std::to_string(imported.ordinal)) : imported.name);
            slot.addr = imported.iatAddress;
            slot.size = thunkWidth;
            p.symbols.push_back(std::move(slot));
            p.imports.push_back(std::move(imported));
        }
        return terminated;
    };
    auto parseImportDirectory = [&](uint32_t tableRva, uint32_t tableSize,
                                    bool delayed) {
        if (!tableRva) return true;
        const auto tableOff = ps.rvaToOffset(tableRva);
        const size_t descriptorSize = delayed ? 32U : 20U;
        if (!tableOff || tableSize < descriptorSize ||
            !rangeInFile(*tableOff, tableSize, d.size()))
            return false;
        const size_t descriptors = tableSize / descriptorSize;
        bool terminated = false;
        for (size_t index = 0; index < descriptors; ++index) {
            const size_t at = *tableOff + index * descriptorSize;
            bool empty = true;
            for (size_t word = 0; word < descriptorSize; word += 4)
                empty &= rd32(d, at + word) == 0;
            if (empty) {
                terminated = true;
                break;
            }
            uint32_t nameRva = 0, lookupRva = 0, iatRva = 0;
            if (!delayed) {
                lookupRva = rd32(d, at);
                nameRva = rd32(d, at + 12);
                iatRva = rd32(d, at + 16);
                if (!lookupRva) lookupRva = iatRva;
            } else {
                const uint32_t attributes = rd32(d, at);
                auto asRva = [&](uint32_t value) -> uint32_t {
                    if (!value || (attributes & 1U)) return value;
                    if (value < p.imageBase ||
                        static_cast<uint64_t>(value) - p.imageBase >
                            std::numeric_limits<uint32_t>::max())
                        return 0;
                    return static_cast<uint32_t>(
                        static_cast<uint64_t>(value) - p.imageBase);
                };
                nameRva = asRva(rd32(d, at + 4));
                iatRva = asRva(rd32(d, at + 12));
                lookupRva = asRva(rd32(d, at + 16));
                if (!lookupRva) lookupRva = iatRva;
            }
            const auto nameOff = ps.rvaToOffset(nameRva);
            if (!nameOff || !lookupRva || !iatRva) return false;
            const std::string library = cstrAt(d, *nameOff, 1024);
            if (library.empty() ||
                !parseThunks(library, lookupRva, iatRva, delayed))
                return false;
            addLibrary(library);
        }
        return terminated;
    };
    const auto imports = directory(1);
    if (imports.first &&
        !parseImportDirectory(imports.first, imports.second, false)) {
        err = "invalid PE import directory";
        return std::nullopt;
    }
    const auto delayImports = directory(13);
    if (delayImports.first &&
        !parseImportDirectory(delayImports.first, delayImports.second, true)) {
        err = "invalid PE delay-import directory";
        return std::nullopt;
    }

    // ---- resource directory tree ----
    const auto resourceDirectory = directory(2);
    if (resourceDirectory.first) {
        const auto resourceOff = ps.rvaToOffset(resourceDirectory.first);
        if (!resourceOff || resourceDirectory.second < 16 ||
            !rangeInFile(*resourceOff, resourceDirectory.second, d.size())) {
            err = "invalid PE resource directory";
            return std::nullopt;
        }
        struct ResourcePath {
            uint32_t typeId = 0, nameId = 0, languageId = 0;
            std::string typeName, name;
        };
        std::set<uint64_t> visited;
        bool validResources = true;
        auto relativeRange = [&](uint32_t relative, uint64_t size) {
            return relative <= resourceDirectory.second &&
                   size <= static_cast<uint64_t>(resourceDirectory.second) - relative &&
                   rangeInFile(static_cast<uint64_t>(*resourceOff) + relative,
                               size, d.size());
        };
        std::function<void(uint32_t, unsigned, ResourcePath)> walk;
        walk = [&](uint32_t relative, unsigned depth, ResourcePath path) {
            if (!validResources || depth > 8 || !relativeRange(relative, 16)) {
                validResources = false;
                return;
            }
            const uint64_t visitKey = (static_cast<uint64_t>(depth) << 32) | relative;
            if (!visited.insert(visitKey).second) return;
            const size_t at = *resourceOff + relative;
            const uint32_t count = static_cast<uint32_t>(rd16(d, at + 12)) +
                                   rd16(d, at + 14);
            if (count > 1'000'000 ||
                !relativeRange(relative + 16, static_cast<uint64_t>(count) * 8)) {
                validResources = false;
                return;
            }
            for (uint32_t index = 0; index < count; ++index) {
                const size_t entry = at + 16 + static_cast<size_t>(index) * 8;
                const uint32_t identifier = rd32(d, entry);
                const uint32_t target = rd32(d, entry + 4);
                ResourcePath next = path;
                uint32_t numeric = 0;
                std::string named;
                if (identifier & 0x80000000U) {
                    const uint32_t stringOffset = identifier & 0x7fffffffU;
                    if (!relativeRange(stringOffset, 2)) {
                        validResources = false;
                        return;
                    }
                    named = utf16ResourceString(d, *resourceOff + stringOffset);
                    if (named.empty()) {
                        validResources = false;
                        return;
                    }
                } else {
                    numeric = identifier & 0xffffU;
                }
                if (depth == 0) {
                    next.typeId = numeric;
                    next.typeName = named.empty()
                        ? standardResourceType(numeric) : named;
                } else if (depth == 1) {
                    next.nameId = numeric;
                    next.name = named;
                } else {
                    next.languageId = numeric;
                }
                const uint32_t targetOffset = target & 0x7fffffffU;
                if (target & 0x80000000U) {
                    walk(targetOffset, depth + 1, std::move(next));
                    continue;
                }
                if (!relativeRange(targetOffset, 16)) {
                    validResources = false;
                    return;
                }
                const size_t dataEntry = *resourceOff + targetOffset;
                const uint32_t dataRva = rd32(d, dataEntry);
                const uint32_t dataSize = rd32(d, dataEntry + 4);
                const auto dataOff = ps.rvaToOffset(dataRva);
                if (!dataOff || !rangeInFile(*dataOff, dataSize, d.size())) {
                    validResources = false;
                    return;
                }
                ResourceEntry resource;
                resource.typeId = next.typeId;
                resource.nameId = next.nameId;
                resource.languageId = next.languageId;
                resource.typeName = next.typeName;
                resource.name = next.name;
                resource.size = dataSize;
                resource.codePage = rd32(d, dataEntry + 8);
                if (!addOk(p.imageBase, dataRva, resource.dataAddress)) {
                    validResources = false;
                    return;
                }
                p.resources.push_back(std::move(resource));
            }
        };
        walk(0, 0, {});
        if (!validResources) {
            err = "invalid PE resource tree";
            return std::nullopt;
        }
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
            // Entry size is 12 bytes for both x64 and ARM64, but ARM64
            // linkers may pad .pdata to a section alignment — accept a
            // trailing partial record instead of rejecting the file.
            if (!rangeInFile(*excOff, excSize, d.size())) {
                err = "invalid PE exception directory";
                return std::nullopt;
            }
            const uint32_t count = excSize / 12;
            const bool archX64 = p.arch == "x86-64" || p.arch == "x86";
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
                // UNWIND_INFO flag/handler layout is x86-64 specific; ARM64
                // packs unwind data into a single 32-bit word (epilog scope
                // codes).  Only x64 gets handler/chained-record recovery.
                if (archX64 && unwindOff &&
                    rangeInFile(*unwindOff, 4, d.size())) {
                    const uint8_t flags = d[*unwindOff] >> 3;
                    const uint8_t codeCount = d[*unwindOff + 2];
                    const size_t slots = (static_cast<size_t>(codeCount) + 1) & ~size_t{1};
                    const size_t handlerOff = *unwindOff + 4 + slots * 2;
                    if ((flags & 0x4) &&
                        rangeInFile(handlerOff, 12, d.size())) {
                        const uint32_t chainedBegin = rd32(d, handlerOff);
                        const uint32_t chainedEnd = rd32(d, handlerOff + 4);
                        const uint32_t chainedUnwind = rd32(d, handlerOff + 8);
                        if (!addOk(p.imageBase, chainedBegin,
                                   region.chainedStart) ||
                            !addOk(p.imageBase, chainedEnd,
                                   region.chainedEnd) ||
                            !addOk(p.imageBase, chainedUnwind,
                                   region.chainedUnwindInfo)) {
                            err = "PE chained unwind address overflow";
                            return std::nullopt;
                        }
                    } else if ((flags & 0x3) &&
                               rangeInFile(handlerOff, 4, d.size())) {
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

    // ---- COFF symbol table ----
    // Link-generated executables carry their local symbols here - including
    // the Itanium C++ ABI metadata names (_ZTV*/_ZTI*/_ZTS*) that drive
    // class, vtable, and RTTI recovery.  Export parsing above only sees DLL
    // exports, so vtables in a plain executable were invisible before.
    if (coff.pointerToSymbolTable && coff.numberOfSymbols) {
        const uint64_t symBase = coff.pointerToSymbolTable;
        const uint64_t strBase = symBase + 18ULL * coff.numberOfSymbols;
        for (uint32_t i = 0; i < coff.numberOfSymbols; ++i) {
            const uint64_t at = symBase + 18ULL * i;
            if (!rangeInFile(at, 18, d.size())) break;
            const int16_t secNum = static_cast<int16_t>(rd16(d, at + 12));
            const uint16_t typeField = rd16(d, at + 14);
            const uint8_t storage = d[at + 16];
            const uint8_t aux = d[at + 17];
            std::string name;
            if (rd32(d, at) == 0) {
                const uint64_t strOff = strBase + rd32(d, at + 4);
                if (rangeInFile(strOff, 1, d.size()))
                    name = cstrAt(d, static_cast<size_t>(strOff), 4096);
            } else {
                name.assign(reinterpret_cast<const char*>(d.data() + at), 8);
                const size_t nul = name.find('\0');
                if (nul != std::string::npos) name.resize(nul);
            }
            i += aux;  // aux records carry no name of their own
            if (name.empty()) continue;
            // EXTERNAL and STATIC cover code and data objects; skip section
            // records, labels, and debug class entries.
            if (storage != 2 && storage != 3) continue;
            const uint32_t value = rd32(d, at + 8);
            uint64_t addr = 0;
            if (secNum > 0) {
                if (static_cast<uint32_t>(secNum) > ps.secs.size()) continue;
                if (!addOk(p.imageBase, ps.secs[secNum - 1].virtualAddress,
                           addr) ||
                    !addOk(addr, value, addr))
                    continue;
            } else if (secNum == -1) {
                addr = value;  // absolute symbol
            } else {
                continue;
            }
            Symbol sym;
            sym.name = std::move(name);
            sym.addr = addr;
            // COFF derived-type 0x20 (IMAGE_SYM_DTYPE_FUNCTION) marks a
            // function; everything else is data (vtables, RTTI, strings).
            sym.isFunction = (typeField & 0x30) == 0x20;
            p.symbols.push_back(std::move(sym));
        }
    }

    // ---- IAT binding: give every import a synthetic stub target ----
    // Unbound IAT slots hold lookup-table RVAs (pointers to
    // IMAGE_IMPORT_BY_NAME records), so an indirect call through the slot
    // resolves to data, not code.  Bind each slot to a synthetic `ret` stub
    // past the end of the image; symbolic exploration and the decompiler
    // then see a stable, named call target (library!name) per import.
    if (!p.imports.empty()) {
        const uint64_t stubAlign = 0x1000;
        const uint64_t stubSize = 16;
        uint64_t stubBase = 0;
        if (!addOk(p.imageBase,
                   (static_cast<uint64_t>(sizeOfImage) + stubAlign - 1) &
                       ~(stubAlign - 1),
                   stubBase)) {
            err = "IAT stub region address overflow";
            return std::nullopt;
        }
        std::vector<uint8_t> stubBytes(p.imports.size() * stubSize, 0xCC);
        for (size_t i = 0; i < p.imports.size(); ++i)
            stubBytes[i * stubSize] = 0xC3;  // ret
        if (stubBytes.size() > maxMappedBytes ||
            !p.memory.addBlock("iat_stubs", stubBase, std::move(stubBytes),
                               static_cast<int>(Perm::R) |
                                   static_cast<int>(Perm::X))) {
            err = "cannot map IAT stub region";
            return std::nullopt;
        }
        for (size_t i = 0; i < p.imports.size(); ++i) {
            const uint64_t stubAddr = stubBase + i * stubSize;
            uint8_t encoded[8] = {0};
            for (int b = 0; b < 8; ++b)
                encoded[b] = static_cast<uint8_t>(stubAddr >> (8 * b));
            if (!p.memory.write(p.imports[i].iatAddress, encoded,
                                is64 ? 8 : 4)) {
                err = "cannot bind IAT slot";
                return std::nullopt;
            }
            p.imports[i].boundAddress = stubAddr;
            Symbol stubSym;
            stubSym.name = p.imports[i].library + "!" +
                           (p.imports[i].byOrdinal
                                ? ("#" + std::to_string(p.imports[i].ordinal))
                                : p.imports[i].name);
            stubSym.addr = stubAddr;
            stubSym.isFunction = true;
            p.symbols.push_back(std::move(stubSym));
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
