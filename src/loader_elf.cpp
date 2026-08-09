// ghra - a Ghidra reimplementation in C++17
// loader_elf.cpp - ELF32/ELF64 loader (hosts are assumed little-endian;
// all multibyte fields are read with explicit LE helpers)
#include "ghra/loader.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ghra {
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
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint32_t SHF_WRITE = 0x1;
constexpr uint32_t SHF_ALLOC = 0x2;
constexpr uint32_t SHF_EXECINSTR = 0x4;
constexpr uint32_t STT_FUNC = 2;
constexpr uint32_t STB_GLOBAL = 1;
constexpr uint32_t STB_WEAK = 2;

template <typename T>
bool rd(const std::vector<uint8_t>& d, size_t off, T& out) {
    if (off + sizeof(T) > d.size()) return false;
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

// Merge overlapping PT_LOAD segments into a single non-overlapping set so the
// MemoryImage (which forbids overlaps) can host the runtime image.
struct Seg {
    uint64_t vaddr, memsz, filesz, off;
    int perm;
};
std::vector<Seg> mergeSegments(std::vector<Seg> segs) {
    std::sort(segs.begin(), segs.end(),
              [](const Seg& a, const Seg& b) { return a.vaddr < b.vaddr; });
    std::vector<Seg> out;
    for (auto& s : segs) {
        if (s.memsz == 0) continue;
        if (!out.empty()) {
            Seg& last = out.back();
            const uint64_t lastEnd = last.vaddr + last.memsz;
            if (s.vaddr <= lastEnd) { // overlap or adjacent
                const uint64_t newEnd = std::max(lastEnd, s.vaddr + s.memsz);
                const uint64_t oldFileszEnd = last.vaddr + last.filesz;
                const uint64_t sFileszEnd = s.vaddr + s.filesz;
                last.filesz = std::max(oldFileszEnd, sFileszEnd) - last.vaddr;
                if (s.filesz > 0 && s.vaddr >= last.vaddr)
                    last.off = s.off - (s.vaddr - last.vaddr);
                last.memsz = newEnd - last.vaddr;
                last.perm |= s.perm;
                continue;
            }
        }
        out.push_back(s);
    }
    return out;
}

std::optional<Program> loadElfImpl(const std::vector<uint8_t>& d,
                                   const std::string& path, std::string& err) {
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

    uint16_t type = 0, machine = 0, phnum = 0, shnum = 0, shstrndx = 0;
    uint16_t phentsize = 0, shentsize = 0;
    uint64_t entry = 0, phoff = 0, shoff = 0;

    if (is64) {
        Ehdr64 h;
        if (!rd(d, 0, h)) { err = "truncated ELF header"; return std::nullopt; }
        type = h.type; machine = h.machine; entry = h.entry;
        phoff = h.phoff; shoff = h.shoff;
        phnum = h.phnum; shnum = h.shnum; shstrndx = h.shstrndx;
        phentsize = h.phentsize; shentsize = h.shentsize;
    } else {
        Ehdr32 h;
        if (!rd(d, 0, h)) { err = "truncated ELF header"; return std::nullopt; }
        type = h.type; machine = h.machine; entry = h.entry;
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
        const size_t off = static_cast<size_t>(phoff) + i * phentsize;
        if (is64) {
            Phdr64 ph;
            if (!rd(d, off, ph)) { err = "truncated program header"; return std::nullopt; }
            if (ph.type != PT_LOAD) continue;
            if (ph.offset + ph.filesz > d.size()) { err = "segment out of file"; return std::nullopt; }
            segs.push_back(Seg{ph.vaddr, ph.memsz, ph.filesz, ph.offset,
                               static_cast<int>(ph.flags & 0x7)});
        } else {
            Phdr32 ph;
            if (!rd(d, off, ph)) { err = "truncated program header"; return std::nullopt; }
            if (ph.type != PT_LOAD) continue;
            if (static_cast<uint64_t>(ph.offset) + ph.filesz > d.size()) { err = "segment out of file"; return std::nullopt; }
            segs.push_back(Seg{ph.vaddr, ph.memsz, ph.filesz, ph.offset,
                               static_cast<int>(ph.flags & 0x7)});
        }
    }
    if (segs.empty()) {
        err = "ELF has no PT_LOAD segments";
        return std::nullopt;
    }
    for (auto& s : mergeSegments(std::move(segs))) {
        std::vector<uint8_t> bytes(static_cast<size_t>(s.memsz), 0);
        const size_t copyN = static_cast<size_t>(
            std::min<uint64_t>(s.filesz, s.memsz));
        if (copyN > 0) {
            std::memcpy(bytes.data(), d.data() + s.off, copyN);
        }
        char name[32];
        std::snprintf(name, sizeof(name), "LOAD:0x%llx",
                      static_cast<unsigned long long>(s.vaddr));
        p.memory.addBlock(name, s.vaddr, std::move(bytes), s.perm);
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
        const size_t off = static_cast<size_t>(shoff) + i * shentsize;
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

    // section names via shstrtab
    std::vector<std::string> secNames(shnum);
    if (shstrndx < shnum) {
        const ShRaw& shstr = shdrs[shstrndx];
        for (uint16_t i = 0; i < shnum; ++i) {
            if (shdrs[i].name < shstr.size) {
                const size_t nOff = static_cast<size_t>(shstr.offset) + shdrs[i].name;
                std::string s;
                while (nOff + s.size() < d.size() && d[nOff + s.size()] != 0)
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
            Section{secNames[i], s.addr, s.size, s.offset, s.size, perm});
    }

    // ---- symbols (symtab + dynsym) ----
    for (uint16_t i = 0; i < shnum; ++i) {
        const ShRaw& s = shdrs[i];
        if (s.type != SHT_SYMTAB && s.type != SHT_DYNSYM) continue;
        if (s.entsize == 0 || s.link >= shnum) continue;
        const size_t symSize = is64 ? sizeof(Sym64) : sizeof(Sym32);
        if (s.entsize < symSize) continue;
        const std::string& strtabName = secNames[s.link];
        const ShRaw& strtab = shdrs[s.link];
        const size_t nSyms = static_cast<size_t>(s.size / s.entsize);
        for (size_t k = 0; k < nSyms; ++k) {
            const size_t off = static_cast<size_t>(s.offset) + k * s.entsize;
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
                const size_t nOff = static_cast<size_t>(strtab.offset) + stName;
                while (nOff + nm.size() < d.size() && d[nOff + nm.size()] != 0)
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
                               const std::string& path, std::string& err) {
    return loadElfImpl(data, path, err);
}

} // namespace ghra
