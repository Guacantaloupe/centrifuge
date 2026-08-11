// centrifuge - a Ghidra reimplementation in C++17
// loader_elf.cpp - ELF32/ELF64 loader (hosts are assumed little-endian;
// all multibyte fields are read with explicit LE helpers)
#include "centrifuge/loader.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace centrifuge {
namespace {

// ---- minimal ELF struct definitions (packed) ----
#pragma pack(push, 1)
struct Ehdr64 {
    uint8_t ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct Shdr64 {
    uint32_t name, type;
    uint64_t flags;
    uint64_t addr, offset, size;
    uint32_t link, info;
    uint64_t addralign, entsize;
};
struct Sym64 {
    uint32_t name;
    uint8_t info, other;
    uint16_t shndx;
    uint64_t value, size;
};
struct Ehdr32 {
    uint8_t ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint32_t entry, phoff, shoff, flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct Shdr32 {
    uint32_t name, type, flags, addr, offset, size, link, info, addralign,
        entsize;
};
struct Sym32 {
    uint32_t name, value, size;
    uint8_t info, other;
    uint16_t shndx;
};
struct Phdr64 {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
};
struct Phdr32 {
    uint32_t type, offset, vaddr, paddr, filesz, memsz, flags, align;
};
#pragma pack(pop)

// ELF constants
constexpr uint32_t SHT_NULL = 0;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint32_t SHF_WRITE = 0x1;
constexpr uint32_t SHF_ALLOC = 0x2;
constexpr uint32_t SHF_EXECINSTR = 0x4;
constexpr uint32_t STT_FUNC = 2;
constexpr uint32_t STB_GLOBAL = 1;
constexpr uint32_t STB_WEAK = 2;
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

const char* elfMachineName(uint16_t m) {
    switch (m) {
    case 3:   return "x86";
    case 8:   return "mips";
    case 20:  return "ppc";
    case 21:  return "ppc64";
    case 22:  return "s390";
    case 40:  return "arm";
    case 50:  return "ia64";
    case 62:  return "x86-64";
    case 183: return "aarch64";
    case 243: return "riscv";
    default:  return "unknown";
    }
}

std::string archForElf(bool is64, uint16_t machine) {
    std::string a = elfMachineName(machine);
    if (a == "riscv") return is64 ? "riscv64" : "riscv32";
    return a;
}

struct Seg {
    uint64_t vaddr, memsz, filesz, off;
    int perm;
};
struct SegGroup {
    uint64_t base = 0;
    uint64_t end = 0;
    int perm = 0;
    std::vector<Seg> members;
};

std::vector<SegGroup> groupSegments(std::vector<Seg> segs) {
    std::sort(segs.begin(), segs.end(),
              [](const Seg& a, const Seg& b) { return a.vaddr < b.vaddr; });
    std::vector<SegGroup> out;
    for (auto& s : segs) {
        if (s.memsz == 0) continue;
        const uint64_t segEnd = s.vaddr + s.memsz; // validated by caller
        if (!out.empty() && s.vaddr <= out.back().end) {
            SegGroup& last = out.back();
            last.end = std::max(last.end, segEnd);
            last.perm |= s.perm;
            last.members.push_back(s);
            continue;
        }
        out.push_back(SegGroup{s.vaddr, segEnd, s.perm, {s}});
    }
    return out;
}

bool readUnsigned(const std::vector<uint8_t>& data, size_t& cursor, size_t end,
                  size_t bytes, uint64_t& value) {
    if (bytes > 8 || cursor > end || bytes > end - cursor || end > data.size())
        return false;
    value = 0;
    for (size_t i = 0; i < bytes; ++i)
        value |= static_cast<uint64_t>(data[cursor + i]) << (i * 8);
    cursor += bytes;
    return true;
}

bool readUleb(const std::vector<uint8_t>& data, size_t& cursor, size_t end,
              uint64_t& value) {
    value = 0;
    for (unsigned shift = 0; cursor < end && shift < 64; shift += 7) {
        const uint8_t byte = data[cursor++];
        value |= static_cast<uint64_t>(byte & 0x7f) << shift;
        if (!(byte & 0x80)) return true;
    }
    return false;
}

bool readSleb(const std::vector<uint8_t>& data, size_t& cursor, size_t end,
              int64_t& value) {
    uint64_t raw = 0;
    unsigned shift = 0;
    uint8_t byte = 0;
    do {
        if (cursor >= end || shift >= 64) return false;
        byte = data[cursor++];
        raw |= static_cast<uint64_t>(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) raw |= (~0ULL) << shift;
    value = static_cast<int64_t>(raw);
    return true;
}

bool decodeDwarfPointer(const std::vector<uint8_t>& data, size_t& cursor,
                        size_t end, uint8_t encoding, size_t pointerSize,
                        uint64_t sectionAddress, size_t sectionFileOffset,
                        uint64_t& result) {
    if (encoding == 0xff) return false;
    const size_t encodedAt = cursor;
    const uint8_t format = encoding & 0x0f;
    uint64_t raw = 0;
    int64_t signedRaw = 0;
    bool signedValue = false;
    if (format == 0x00) {
        if (!readUnsigned(data, cursor, end, pointerSize, raw)) return false;
    } else if (format == 0x01) {
        if (!readUleb(data, cursor, end, raw)) return false;
    } else if (format == 0x02 || format == 0x03 || format == 0x04) {
        const size_t bytes = format == 0x02 ? 2 : format == 0x03 ? 4 : 8;
        if (!readUnsigned(data, cursor, end, bytes, raw)) return false;
    } else if (format == 0x09) {
        if (!readSleb(data, cursor, end, signedRaw)) return false;
        signedValue = true;
    } else if (format == 0x0a || format == 0x0b || format == 0x0c) {
        const size_t bytes = format == 0x0a ? 2 : format == 0x0b ? 4 : 8;
        if (!readUnsigned(data, cursor, end, bytes, raw)) return false;
        const unsigned bits = static_cast<unsigned>(bytes * 8);
        signedRaw = static_cast<int64_t>((raw ^ (1ULL << (bits - 1))) -
                                         (1ULL << (bits - 1)));
        signedValue = true;
    } else {
        return false;
    }
    uint64_t base = 0;
    switch (encoding & 0x70) {
    case 0x00: break;
    case 0x10:
        base = sectionAddress + (encodedAt - sectionFileOffset);
        break;
    case 0x30:
        base = sectionAddress;
        break;
    default: return false;
    }
    if (signedValue) {
        if (signedRaw < 0 && static_cast<uint64_t>(-signedRaw) > base) return false;
        result = signedRaw < 0 ? base - static_cast<uint64_t>(-signedRaw)
                               : base + static_cast<uint64_t>(signedRaw);
    } else {
        if (raw > std::numeric_limits<uint64_t>::max() - base) return false;
        result = base + raw;
    }
    return true;
}

struct DwarfCieInfo {
    std::string augmentation;
    uint8_t fdeEncoding = 0;
    uint8_t lsdaEncoding = 0xff;
    uint64_t personality = 0;
};

std::vector<ExceptionRegion> parseDwarfFrames(const std::vector<uint8_t>& data,
                                               uint64_t fileOffset,
                                               uint64_t sectionSize,
                                               uint64_t sectionAddress,
                                               bool isEhFrame,
                                               size_t pointerSize) {
    std::vector<ExceptionRegion> regions;
    if (!rangeInFile(fileOffset, sectionSize, data.size())) return regions;
    const size_t sectionStart = static_cast<size_t>(fileOffset);
    const size_t sectionEnd = sectionStart + static_cast<size_t>(sectionSize);
    std::map<size_t, DwarfCieInfo> cies;
    size_t cursor = sectionStart;
    while (cursor + 4 <= sectionEnd) {
        const size_t entryStart = cursor;
        uint64_t length = 0;
        if (!readUnsigned(data, cursor, sectionEnd, 4, length)) break;
        if (length == 0) break;
        size_t idSize = 4;
        if (length == 0xffffffff) {
            if (!readUnsigned(data, cursor, sectionEnd, 8, length)) break;
            idSize = 8;
        }
        if (length > sectionEnd - cursor) break;
        const size_t entryEnd = cursor + static_cast<size_t>(length);
        const size_t idField = cursor;
        uint64_t identifier = 0;
        if (!readUnsigned(data, cursor, entryEnd, idSize, identifier)) break;
        const bool cie = isEhFrame ? identifier == 0
                                   : identifier == (idSize == 4 ? 0xffffffffULL
                                                                : ~0ULL);
        if (cie) {
            DwarfCieInfo info;
            if (cursor >= entryEnd) { cursor = entryEnd; continue; }
            const uint8_t version = data[cursor++];
            while (cursor < entryEnd && data[cursor])
                info.augmentation.push_back(static_cast<char>(data[cursor++]));
            if (cursor >= entryEnd) { cursor = entryEnd; continue; }
            ++cursor;
            uint64_t codeAlignment = 0, returnRegister = 0;
            int64_t dataAlignment = 0;
            if (!readUleb(data, cursor, entryEnd, codeAlignment) ||
                !readSleb(data, cursor, entryEnd, dataAlignment)) {
                cursor = entryEnd; continue;
            }
            if (version == 1) {
                if (cursor >= entryEnd) { cursor = entryEnd; continue; }
                returnRegister = data[cursor++];
            } else if (!readUleb(data, cursor, entryEnd, returnRegister)) {
                cursor = entryEnd; continue;
            }
            (void)codeAlignment; (void)dataAlignment; (void)returnRegister;
            if (!info.augmentation.empty() && info.augmentation[0] == 'z') {
                uint64_t augmentationLength = 0;
                if (!readUleb(data, cursor, entryEnd, augmentationLength) ||
                    augmentationLength > entryEnd - cursor) {
                    cursor = entryEnd; continue;
                }
                const size_t augmentationEnd = cursor +
                    static_cast<size_t>(augmentationLength);
                for (size_t i = 1; i < info.augmentation.size() &&
                                   cursor < augmentationEnd; ++i) {
                    const char kind = info.augmentation[i];
                    if (kind == 'R') info.fdeEncoding = data[cursor++];
                    else if (kind == 'L') info.lsdaEncoding = data[cursor++];
                    else if (kind == 'P') {
                        const uint8_t encoding = data[cursor++];
                        decodeDwarfPointer(data, cursor, augmentationEnd, encoding,
                                           pointerSize, sectionAddress,
                                           sectionStart, info.personality);
                    }
                }
                cursor = augmentationEnd;
            }
            cies[entryStart] = info;
        } else {
            const size_t cieStart = isEhFrame
                ? (identifier <= idField ? idField - static_cast<size_t>(identifier)
                                         : sectionEnd)
                : sectionStart + static_cast<size_t>(identifier);
            const auto found = cies.find(cieStart);
            if (found != cies.end()) {
                const DwarfCieInfo& info = found->second;
                uint64_t start = 0, range = 0;
                const uint8_t locationEncoding = info.fdeEncoding;
                if (decodeDwarfPointer(data, cursor, entryEnd, locationEncoding,
                                       pointerSize, sectionAddress, sectionStart,
                                       start) &&
                    decodeDwarfPointer(data, cursor, entryEnd,
                                       locationEncoding & 0x0f, pointerSize,
                                       sectionAddress, sectionStart, range) &&
                    range <= std::numeric_limits<uint64_t>::max() - start) {
                    uint64_t lsda = 0;
                    if (!info.augmentation.empty() && info.augmentation[0] == 'z') {
                        uint64_t augmentationLength = 0;
                        if (readUleb(data, cursor, entryEnd, augmentationLength) &&
                            augmentationLength <= entryEnd - cursor) {
                            const size_t augmentationEnd = cursor +
                                static_cast<size_t>(augmentationLength);
                            if (info.lsdaEncoding != 0xff)
                                decodeDwarfPointer(data, cursor, augmentationEnd,
                                                   info.lsdaEncoding, pointerSize,
                                                   sectionAddress, sectionStart, lsda);
                            cursor = augmentationEnd;
                        }
                    }
                    ExceptionRegion region;
                    region.kind = ExceptionRegion::DWARF_CFI;
                    region.start = start;
                    region.end = start + range;
                    region.unwindInfo = sectionAddress + (entryStart - sectionStart);
                    region.handler = info.personality;
                    region.languageData = lsda;
                    regions.push_back(region);
                }
            }
        }
        cursor = entryEnd;
    }
    return regions;
}

void parseLsda(const std::vector<uint8_t>& data, size_t fileOffset, size_t end,
               uint64_t sectionAddress, size_t sectionFileOffset,
               ExceptionRegion& region, size_t pointerSize) {
    if (fileOffset >= end || end > data.size()) return;
    size_t cursor = fileOffset;
    const uint8_t lpEncoding = data[cursor++];
    uint64_t landingPadBase = region.start;
    if (lpEncoding != 0xff &&
        !decodeDwarfPointer(data, cursor, end, lpEncoding, pointerSize,
                            sectionAddress, sectionFileOffset, landingPadBase))
        return;
    if (cursor >= end) return;
    const uint8_t typeEncoding = data[cursor++];
    if (typeEncoding != 0xff) {
        uint64_t typeOffset = 0;
        if (!readUleb(data, cursor, end, typeOffset)) return;
        (void)typeOffset;
    }
    if (cursor >= end) return;
    const uint8_t callSiteEncoding = data[cursor++];
    uint64_t tableLength = 0;
    if (!readUleb(data, cursor, end, tableLength) || tableLength > end - cursor)
        return;
    const size_t tableEnd = cursor + static_cast<size_t>(tableLength);
    while (cursor < tableEnd) {
        uint64_t start = 0, length = 0, landing = 0, action = 0;
        const uint8_t valueEncoding = callSiteEncoding & 0x0f;
        if (!decodeDwarfPointer(data, cursor, tableEnd, valueEncoding,
                                pointerSize, sectionAddress, sectionFileOffset,
                                start) ||
            !decodeDwarfPointer(data, cursor, tableEnd, valueEncoding,
                                pointerSize, sectionAddress, sectionFileOffset,
                                length) ||
            !decodeDwarfPointer(data, cursor, tableEnd, valueEncoding,
                                pointerSize, sectionAddress, sectionFileOffset,
                                landing) ||
            !readUleb(data, cursor, tableEnd, action))
            break;
        if (!landing || start > std::numeric_limits<uint64_t>::max() -
                                  landingPadBase ||
            length > std::numeric_limits<uint64_t>::max() -
                         (landingPadBase + start))
            continue;
        region.handlers.push_back({landingPadBase + start,
                                   landingPadBase + start + length,
                                   landingPadBase + landing,
                                   static_cast<int64_t>(action)});
    }
}

std::optional<Program> loadElfImpl(const std::vector<uint8_t>& d,
                                   const std::string& path,
                                   uint64_t maxMappedBytes,
                                   std::string& err) {
    if (d.size() < 16) {
        err = "ELF file too small";
        return std::nullopt;
    }
    const uint8_t elfClass = d[4];
    if (elfClass != 1 && elfClass != 2) {
        err = "bad ELF class";
        return std::nullopt;
    }
    const bool is64 = (elfClass == 2);

    uint16_t machine = 0, phnum = 0, shnum = 0, shstrndx = 0;
    uint16_t phentsize = 0, shentsize = 0;
    uint64_t entry = 0, phoff = 0, shoff = 0;

    if (is64) {
        Ehdr64 h;
        if (!rd(d, 0, h)) { err = "truncated ELF header"; return std::nullopt; }
        machine = h.machine; entry = h.entry;
        phoff = h.phoff; shoff = h.shoff;
        phnum = h.phnum; shnum = h.shnum; shstrndx = h.shstrndx;
        phentsize = h.phentsize; shentsize = h.shentsize;
    } else {
        Ehdr32 h;
        if (!rd(d, 0, h)) { err = "truncated ELF header"; return std::nullopt; }
        machine = h.machine; entry = h.entry;
        phoff = h.phoff; shoff = h.shoff;
        phnum = h.phnum; shnum = h.shnum; shstrndx = h.shstrndx;
        phentsize = h.phentsize; shentsize = h.shentsize;
    }

    Program p;
    p.path = path;
    p.format = is64 ? "ELF64" : "ELF32";
    p.arch = archForElf(is64, machine);
    p.entryPoint = entry;

    // ---- program headers -> runtime memory image ----
    if (phentsize < (is64 ? sizeof(Phdr64) : sizeof(Phdr32)) || phnum == 0 ||
        phoff == 0) {
        err = "ELF has no usable program headers";
        return std::nullopt;
    }
    std::vector<Seg> segs;
    for (uint16_t i = 0; i < phnum; ++i) {
        uint64_t entryOff = 0;
        if (!addOk(phoff, static_cast<uint64_t>(i) * phentsize, entryOff) ||
            !rangeInFile(entryOff, phentsize, d.size())) {
            err = "truncated program header";
            return std::nullopt;
        }
        const size_t off = static_cast<size_t>(entryOff);
        if (is64) {
            Phdr64 ph;
            if (!rd(d, off, ph)) { err = "truncated program header"; return std::nullopt; }
            if (ph.type != PT_LOAD) continue;
            uint64_t end = 0;
            if (ph.filesz > ph.memsz || !rangeInFile(ph.offset, ph.filesz, d.size()) ||
                !addOk(ph.vaddr, ph.memsz, end) || ph.memsz > maxMappedBytes) {
                err = "invalid load segment range";
                return std::nullopt;
            }
            segs.push_back(Seg{ph.vaddr, ph.memsz, ph.filesz, ph.offset,
                               static_cast<int>(ph.flags & 0x7)});
        } else {
            Phdr32 ph;
            if (!rd(d, off, ph)) { err = "truncated program header"; return std::nullopt; }
            if (ph.type != PT_LOAD) continue;
            uint64_t end = 0;
            if (ph.filesz > ph.memsz || !rangeInFile(ph.offset, ph.filesz, d.size()) ||
                !addOk(ph.vaddr, ph.memsz, end) || ph.memsz > maxMappedBytes) {
                err = "invalid load segment range";
                return std::nullopt;
            }
            segs.push_back(Seg{ph.vaddr, ph.memsz, ph.filesz, ph.offset,
                               static_cast<int>(ph.flags & 0x7)});
        }
    }
    if (segs.empty()) {
        err = "ELF has no PT_LOAD segments";
        return std::nullopt;
    }
    uint64_t mappedTotal = 0;
    for (auto& group : groupSegments(std::move(segs))) {
        const uint64_t groupSize = group.end - group.base;
        if (groupSize > maxMappedBytes || mappedTotal > maxMappedBytes - groupSize ||
            groupSize > SIZE_MAX) {
            err = "merged load range too large";
            return std::nullopt;
        }
        mappedTotal += groupSize;
        std::vector<uint8_t> bytes(static_cast<size_t>(groupSize), 0);
        for (const auto& s : group.members) {
            if (s.filesz == 0) continue;
            const size_t dstOff = static_cast<size_t>(s.vaddr - group.base);
            const size_t copyN = static_cast<size_t>(s.filesz);
            std::memcpy(bytes.data() + dstOff,
                        d.data() + static_cast<size_t>(s.off), copyN);
        }
        char name[32];
        std::snprintf(name, sizeof(name), "LOAD:0x%llx",
                      static_cast<unsigned long long>(group.base));
        if (!p.memory.addBlock(name, group.base, std::move(bytes), group.perm)) {
            err = "overlapping or invalid load range";
            return std::nullopt;
        }
    }

    // ---- section headers ----
    if (shentsize < (is64 ? sizeof(Shdr64) : sizeof(Shdr32)) || shnum == 0 ||
        shoff == 0) {
        err = "ELF has no usable section table";
        return std::nullopt;
    }
    struct ShRaw {
        uint32_t name, type, flags, link;
        uint64_t addr, offset, size, entsize;
    };
    std::vector<ShRaw> shdrs;
    shdrs.reserve(shnum);
    for (uint16_t i = 0; i < shnum; ++i) {
        uint64_t entryOff = 0;
        if (!addOk(shoff, static_cast<uint64_t>(i) * shentsize, entryOff) ||
            !rangeInFile(entryOff, shentsize, d.size())) {
            err = "truncated section header";
            return std::nullopt;
        }
        const size_t off = static_cast<size_t>(entryOff);
        ShRaw s{};
        if (is64) {
            Shdr64 h;
            if (!rd(d, off, h)) { err = "truncated section header"; return std::nullopt; }
            s = ShRaw{h.name, h.type, static_cast<uint32_t>(h.flags),
                      static_cast<uint32_t>(h.link),
                      h.addr, h.offset, h.size, h.entsize};
        } else {
            Shdr32 h;
            if (!rd(d, off, h)) { err = "truncated section header"; return std::nullopt; }
            s = ShRaw{h.name, h.type, h.flags, h.link, h.addr, h.offset,
                      h.size, h.entsize};
        }
        shdrs.push_back(s);
    }

    for (const auto& s : shdrs) {
        if (s.type != SHT_NOBITS && s.size != 0 &&
            !rangeInFile(s.offset, s.size, d.size())) {
            err = "section out of file";
            return std::nullopt;
        }
    }

    // section names via shstrtab
    std::vector<std::string> secNames(shnum);
    if (shstrndx < shnum) {
        const ShRaw& shstr = shdrs[shstrndx];
        if (shstr.type != SHT_STRTAB ||
            !rangeInFile(shstr.offset, shstr.size, d.size())) {
            err = "invalid section-name string table";
            return std::nullopt;
        }
        for (uint16_t i = 0; i < shnum; ++i) {
            if (shdrs[i].name < shstr.size) {
                const size_t nOff = static_cast<size_t>(shstr.offset + shdrs[i].name);
                const size_t nEnd = static_cast<size_t>(shstr.offset + shstr.size);
                std::string s;
                while (nOff + s.size() < nEnd && d[nOff + s.size()] != 0)
                    s.push_back(static_cast<char>(d[nOff + s.size()]));
                secNames[i] = std::move(s);
            }
        }
    }

    for (uint16_t i = 1; i < shnum; ++i) {
        const ShRaw& s = shdrs[i];
        if (s.type == SHT_NULL) continue;
        int perm = 0;
        if (s.flags & SHF_EXECINSTR) perm |= static_cast<int>(Perm::X);
        if (s.flags & SHF_WRITE) perm |= static_cast<int>(Perm::W);
        if (s.flags & SHF_ALLOC) perm |= static_cast<int>(Perm::R);
        p.sections.push_back(
            Section{secNames[i], s.addr, s.size, s.offset,
                    s.type == SHT_NOBITS ? 0 : s.size, perm});
        if (secNames[i] == ".eh_frame" || secNames[i] == ".debug_frame") {
            std::vector<ExceptionRegion> decoded = parseDwarfFrames(
                d, s.offset, s.size, s.addr, secNames[i] == ".eh_frame",
                is64 ? 8 : 4);
            if (decoded.empty()) {
                ExceptionRegion region;
                region.kind = ExceptionRegion::DWARF_CFI;
                region.unwindInfo = s.addr;
                p.exceptionRegions.push_back(region);
            } else {
                p.exceptionRegions.insert(p.exceptionRegions.end(),
                                          decoded.begin(), decoded.end());
            }
        }
    }

    for (ExceptionRegion& region : p.exceptionRegions) {
        if (region.kind != ExceptionRegion::DWARF_CFI || !region.languageData)
            continue;
        for (const ShRaw& section : shdrs) {
            if (region.languageData < section.addr ||
                region.languageData - section.addr >= section.size)
                continue;
            const uint64_t relative = region.languageData - section.addr;
            if (relative > std::numeric_limits<size_t>::max() - section.offset)
                break;
            const size_t lsdaOffset = static_cast<size_t>(section.offset + relative);
            const size_t sectionEnd = static_cast<size_t>(section.offset + section.size);
            parseLsda(d, lsdaOffset, sectionEnd, section.addr,
                      static_cast<size_t>(section.offset), region, is64 ? 8 : 4);
            break;
        }
    }

    // ---- symbols (symtab + dynsym) ----
    for (uint16_t i = 0; i < shnum; ++i) {
        const ShRaw& s = shdrs[i];
        if (s.type != SHT_SYMTAB && s.type != SHT_DYNSYM) continue;
        if (s.entsize == 0 || s.link >= shnum) continue;
        const size_t symSize = is64 ? sizeof(Sym64) : sizeof(Sym32);
        if (s.entsize < symSize) continue;
        const ShRaw& strtab = shdrs[s.link];
        if (strtab.type != SHT_STRTAB ||
            !rangeInFile(strtab.offset, strtab.size, d.size()))
            continue;
        const size_t nSyms = static_cast<size_t>(s.size / s.entsize);
        for (size_t k = 0; k < nSyms; ++k) {
            uint64_t symOff = 0;
            if (k > std::numeric_limits<uint64_t>::max() / s.entsize ||
                !addOk(s.offset, static_cast<uint64_t>(k) * s.entsize, symOff) ||
                !rangeInFile(symOff, symSize, d.size()))
                break;
            const size_t off = static_cast<size_t>(symOff);
            uint32_t stName = 0;
            uint8_t stInfo = 0;
            uint64_t stValue = 0, stSize = 0;
            if (is64) {
                Sym64 sym;
                if (!rd(d, off, sym)) break;
                stName = sym.name; stInfo = sym.info;
                stValue = sym.value; stSize = sym.size;
            } else {
                Sym32 sym;
                if (!rd(d, off, sym)) break;
                stName = sym.name; stInfo = sym.info;
                stValue = sym.value; stSize = sym.size;
            }
            if ((stInfo & 0xf) != STT_FUNC) continue;
            if ((stInfo >> 4) != STB_GLOBAL && (stInfo >> 4) != STB_WEAK)
                continue;
            if (stValue == 0) continue;
            std::string nm;
            if (stName < strtab.size) {
                const size_t nOff = static_cast<size_t>(strtab.offset + stName);
                const size_t nEnd = static_cast<size_t>(strtab.offset + strtab.size);
                while (nOff + nm.size() < nEnd && d[nOff + nm.size()] != 0)
                    nm.push_back(static_cast<char>(d[nOff + nm.size()]));
            }
            Symbol sym;
            sym.name = std::move(nm);
            sym.addr = stValue;
            sym.size = stSize;
            sym.isFunction = true;
            sym.isExported = (s.type == SHT_DYNSYM);
            p.symbols.push_back(std::move(sym));
        }
    }

    // entry point as a pseudo-symbol so downstream passes always see it
    if (p.entryPoint != 0) {
        Symbol e;
        e.name = "entry";
        e.addr = p.entryPoint;
        e.size = 0;
        e.isFunction = true;
        p.symbols.push_back(std::move(e));
    }

    return p;
}

} // namespace

std::optional<Program> loadElf(const std::vector<uint8_t>& data,
                               const std::string& path,
                               uint64_t maxMappedBytes, std::string& err) {
    return loadElfImpl(data, path, maxMappedBytes, err);
}

} // namespace centrifuge
