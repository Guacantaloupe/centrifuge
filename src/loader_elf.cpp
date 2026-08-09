// centrifuge - a Ghidra reimplementation in C++17
// loader_elf.cpp - ELF32/ELF64 loader (hosts are assumed little-endian;
// all multibyte fields are read with explicit LE helpers)
#include "centrifuge/loader.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
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
            ExceptionRegion region;
            region.kind = ExceptionRegion::DWARF_CFI;
            region.unwindInfo = s.addr;
            region.languageData = s.size;
            p.exceptionRegions.push_back(region);
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
