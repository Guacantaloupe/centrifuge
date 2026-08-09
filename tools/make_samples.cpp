// ghra - a Ghidra reimplementation in C++17
// tools/make_samples.cpp - writes hand-crafted test binaries (pure C++17)
//
// Produces, byte-for-byte, the same samples the old Python generator did:
//   samples/sample_elf64    - ELF64 x86-64 ET_EXEC, 2 funcs + 1 data sym
//   samples/sample_elf32    - ELF32 x86    ET_EXEC, same shape
//   samples/sample_pe64.exe - PE32+ x86-64 with 2 exports + entry stub
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Buf {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) {
        b.push_back(static_cast<uint8_t>(v));
        b.push_back(static_cast<uint8_t>(v >> 8));
    }
    void u32(uint32_t v) {
        b.push_back(static_cast<uint8_t>(v));
        b.push_back(static_cast<uint8_t>(v >> 8));
        b.push_back(static_cast<uint8_t>(v >> 16));
        b.push_back(static_cast<uint8_t>(v >> 24));
    }
    void u64(uint64_t v) {
        u32(static_cast<uint32_t>(v));
        u32(static_cast<uint32_t>(v >> 32));
    }
    void bytes(const uint8_t* p, size_t n) { b.insert(b.end(), p, p + n); }
    void str(const char* s) { b.insert(b.end(), s, s + std::strlen(s) + 1); }
    void pad(size_t n, uint8_t v = 0) {
        while (b.size() < n) b.push_back(v);
    }
    size_t size() const { return b.size(); }
    const uint8_t* data() const { return b.data(); }
};

void put32(std::vector<uint8_t>& v, size_t off, uint32_t val) {
    v[off] = static_cast<uint8_t>(val);
    v[off + 1] = static_cast<uint8_t>(val >> 8);
    v[off + 2] = static_cast<uint8_t>(val >> 16);
    v[off + 3] = static_cast<uint8_t>(val >> 24);
}
void put64(std::vector<uint8_t>& v, size_t off, uint64_t val) {
    put32(v, off, static_cast<uint32_t>(val));
    put32(v, off + 4, static_cast<uint32_t>(val >> 32));
}
void put16(std::vector<uint8_t>& v, size_t off, uint16_t val) {
    v[off] = static_cast<uint8_t>(val);
    v[off + 1] = static_cast<uint8_t>(val >> 8);
}
void putStr(std::vector<uint8_t>& v, size_t off, const char* s) {
    std::memcpy(v.data() + off, s, std::strlen(s) + 1);
}

// ---------------------------------------------------------------- ELF
std::vector<uint8_t> buildElf(bool is64) {
    const uint32_t textVa = is64 ? 0x401000 : 0x8048000;
    const uint32_t dataVa = is64 ? 0x402000 : 0x8049000;
    const uint16_t machine = is64 ? 62 : 3;
    const size_t ehsz = is64 ? 64 : 52;
    const size_t phsz = is64 ? 56 : 32;
    const size_t shsz = is64 ? 64 : 40;
    const size_t symsz = is64 ? 24 : 16;

    static const uint8_t textMain64[] = {
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x17, 0x00, 0x00, 0x00, // main
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3};
    static const uint8_t textHelper64[] = {0x55, 0x48, 0x89, 0xE5,
                                           0xB8, 0x2A, 0x00, 0x00,
                                           0x00, 0x5D, 0xC3};
    static const uint8_t textMain32[] = {
        0x55, 0x89, 0xE5, 0xE8, 0x18, 0x00, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3};
    static const uint8_t textHelper32[] = {0x55, 0x89, 0xE5, 0xB8,
                                           0x2A, 0x00, 0x00, 0x00,
                                           0x5D, 0xC3};

    std::vector<uint8_t> text(is64 ? textMain64 : textMain32,
                              (is64 ? textMain64 : textMain32) +
                                  (is64 ? sizeof(textMain64)
                                        : sizeof(textMain32)));
    {
        const uint8_t* h = is64 ? textHelper64 : textHelper32;
        text.insert(text.end(), h,
                    h + (is64 ? sizeof(textHelper64) : sizeof(textHelper32)));
    }
    text.resize(0x30, 0xCC); // pad with int3
    const std::string dataStr = "hello from ghra sample";
    std::vector<uint8_t> data(dataStr.begin(), dataStr.end());
    data.push_back(0);

    // string tables (leading NUL required; build as std::string so the
    // embedded NULs survive and find() works)
    std::string shstr = std::string(1, '\0');
    for (const char* n : {".text", ".data", ".symtab", ".strtab",
                          ".shstrtab"})
        shstr += std::string(n) + '\0';
    std::string strtab = std::string(1, '\0');
    for (const char* n : {"main", "helper", "msg"})
        strtab += std::string(n) + '\0';
    const std::vector<uint8_t> shstrV(shstr.begin(), shstr.end());
    const std::vector<uint8_t> strtabV(strtab.begin(), strtab.end());

    const size_t shdrOff = ehsz + 2 * phsz;   // where the shdr table goes
    const size_t shstrOff = shdrOff + 6 * shsz;
    const size_t strtabOff = shstrOff + shstr.size();
    const size_t symtabOff = (strtabOff + strtab.size() + 7) & ~size_t(7);

    const char* secNames[5] = {".text", ".data", ".symtab", ".strtab",
                               ".shstrtab"};
    size_t nameOff[5] = {};
    for (int i = 0; i < 5; ++i) nameOff[i] = shstr.find(secNames[i]);
    const size_t offMain = strtab.find("main");
    const size_t offHelper = strtab.find("helper");
    const size_t offMsg = strtab.find("msg");

    Buf out;
    // ELF header
    out.u8(0x7F); out.u8('E'); out.u8('L'); out.u8('F');
    out.u8(is64 ? 2 : 1); out.u8(1); out.u8(1); out.u8(0);
    out.pad(16);
    out.u16(2);          // ET_EXEC
    out.u16(machine);
    out.u32(1);          // e_version
    if (is64) out.u64(textVa);
    else out.u32(textVa);
    if (is64) out.u64(ehsz); // e_phoff: right after the ELF header
    else out.u32(static_cast<uint32_t>(ehsz));
    if (is64) out.u64(shdrOff); // e_shoff: right after program headers
    else out.u32(static_cast<uint32_t>(shdrOff));
    out.u32(0);          // e_flags
    out.u16(static_cast<uint16_t>(ehsz));
    out.u16(static_cast<uint16_t>(phsz));
    out.u16(2);          // e_phnum
    out.u16(static_cast<uint16_t>(shsz));
    out.u16(6);          // e_shnum
    out.u16(5);          // e_shstrndx

    // program headers: LOAD .text (R+X), LOAD .data (R+W)
    if (is64) {
        out.u32(1); out.u32(5); out.u64(0x1000); out.u64(textVa);
        out.u64(textVa); out.u64(text.size()); out.u64(text.size());
        out.u64(0x1000);
        out.u32(1); out.u32(6); out.u64(0x2000); out.u64(dataVa);
        out.u64(dataVa); out.u64(data.size()); out.u64(data.size());
        out.u64(0x1000);
    } else {
        out.u32(1); out.u32(0x1000); out.u32(textVa); out.u32(textVa);
        out.u32(static_cast<uint32_t>(text.size()));
        out.u32(static_cast<uint32_t>(text.size()));
        out.u32(5); out.u32(0x1000);
        out.u32(1); out.u32(0x2000); out.u32(dataVa); out.u32(dataVa);
        out.u32(static_cast<uint32_t>(data.size()));
        out.u32(static_cast<uint32_t>(data.size()));
        out.u32(6); out.u32(0x1000);
    }

    // section headers: null, .text, .data, .symtab, .strtab, .shstrtab
    auto sh = [&](uint32_t name, uint32_t type, uint32_t flags, uint64_t addr,
                  uint64_t off, uint64_t size, uint32_t link, uint32_t info,
                  uint64_t align, uint64_t entsz) {
        if (is64) {
            out.u32(name); out.u32(type); out.u64(flags); out.u64(addr);
            out.u64(off); out.u64(size); out.u32(link); out.u32(info);
            out.u64(align); out.u64(entsz);
        } else {
            out.u32(name); out.u32(type); out.u32(flags);
            out.u32(static_cast<uint32_t>(addr));
            out.u32(static_cast<uint32_t>(off));
            out.u32(static_cast<uint32_t>(size));
            out.u32(link); out.u32(info);
            out.u32(static_cast<uint32_t>(align));
            out.u32(static_cast<uint32_t>(entsz));
        }
    };
    sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    sh(static_cast<uint32_t>(nameOff[0]), 1, 0x6, textVa, 0x1000,
       text.size(), 0, 0, 16, 0);
    sh(static_cast<uint32_t>(nameOff[1]), 1, 0x3, dataVa, 0x2000,
       data.size(), 0, 0, 0, 0);
    sh(static_cast<uint32_t>(nameOff[2]), 2, 0, 0, symtabOff, 4 * symsz, 4, 1,
       8, symsz);
    sh(static_cast<uint32_t>(nameOff[3]), 3, 0, 0, strtabOff, strtab.size(),
       0, 0, 0, 0);
    sh(static_cast<uint32_t>(nameOff[4]), 3, 0, 0, shstrOff, shstr.size(), 0,
       0, 0, 0);

    out.bytes(shstrV.data(), shstrV.size());
    out.bytes(strtabV.data(), strtabV.size());
    out.pad(symtabOff);

    // symbols: null, main, helper, msg
    auto sym = [&](uint32_t name, uint64_t value, uint64_t size,
                   uint8_t info, uint16_t shndx) {
        if (is64) {
            out.u32(name); out.u8(info); out.u8(0); out.u16(shndx);
            out.u64(value); out.u64(size);
        } else {
            out.u32(name); out.u32(static_cast<uint32_t>(value));
            out.u32(static_cast<uint32_t>(size)); out.u8(info); out.u8(0);
            out.u16(shndx);
        }
    };
    sym(0, 0, 0, 0, 0);
    sym(static_cast<uint32_t>(offMain), textVa, 0x10, 0x12, 1);
    sym(static_cast<uint32_t>(offHelper), textVa + 0x20, 0x0C, 0x12, 1);
    sym(static_cast<uint32_t>(offMsg), dataVa, 0x15, 0x11, 2);

    out.pad(0x1000);
    out.bytes(text.data(), text.size());
    out.pad(0x2000);
    out.bytes(data.data(), data.size());
    return out.b;
}

// ---------------------------------------------------------------- PE32+
std::vector<uint8_t> buildPe64() {
    const uint64_t imgbase = 0x140000000ULL;
    const uint32_t entryRva = 0x1009;
    static const uint8_t text[] = {
        0x8D, 0x04, 0x11, 0xC3,                         // sample_add
        0x89, 0xC8, 0x29, 0xD0, 0xC3,                   // sample_sub
        0x48, 0x83, 0xEC, 0x28, 0xB8, 0x2A, 0x00, 0x00, // entry stub
        0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3};
    std::vector<uint8_t> textV(text, text + sizeof(text));
    textV.resize(0x30, 0xCC);

    const uint32_t expRva = 0x2000;
    const uint32_t dllnameOff = 0x28, funcsOff = 0x38, namesOff = 0x40;
    const uint32_t name1Off = 0x48, name2Off = 0x54, ordsOff = 0x60;
    const uint32_t expSize = 0x70;

    std::vector<uint8_t> rdata(0x100, 0);
    // IMAGE_EXPORT_DIRECTORY
    put32(rdata, 0, 0);
    put32(rdata, 4, 0);
    put16(rdata, 8, 0);
    put16(rdata, 10, 0);
    put32(rdata, 12, expRva + dllnameOff); // Name
    put32(rdata, 16, 1);                   // Base
    put32(rdata, 20, 2);                   // NumberOfFunctions
    put32(rdata, 24, 2);                   // NumberOfNames
    put32(rdata, 28, expRva + funcsOff);   // AddressOfFunctions
    put32(rdata, 32, expRva + namesOff);   // AddressOfNames
    put32(rdata, 36, expRva + ordsOff);    // AddressOfNameOrdinals
    putStr(rdata, dllnameOff, "sample_pe64.dll");
    put32(rdata, funcsOff + 0, 0x1000);
    put32(rdata, funcsOff + 4, 0x1004);
    put32(rdata, namesOff + 0, expRva + name1Off);
    put32(rdata, namesOff + 4, expRva + name2Off);
    putStr(rdata, name1Off, "sample_add");
    putStr(rdata, name2Off, "sample_sub");
    put16(rdata, ordsOff + 0, 0);
    put16(rdata, ordsOff + 2, 1);

    std::vector<uint8_t> opt(240, 0);
    put16(opt, 0, 0x20B);              // magic PE32+
    put32(opt, 4, 0x40);               // SizeOfCode
    put32(opt, 8, 0x100);              // SizeOfInitializedData
    put32(opt, 16, entryRva);          // AddressOfEntryPoint
    put32(opt, 20, 0x1000);            // BaseOfCode
    put64(opt, 24, imgbase);           // ImageBase
    put32(opt, 32, 0x1000);            // SectionAlignment
    put32(opt, 36, 0x200);             // FileAlignment
    put16(opt, 40, 6);                 // OS version
    put16(opt, 48, 6);                 // subsystem version
    put32(opt, 56, 0x3000);            // SizeOfImage
    put32(opt, 60, 0x200);             // SizeOfHeaders
    put16(opt, 68, 3);                 // Subsystem = CUI
    put16(opt, 70, 0x160);             // DllCharacteristics
    put64(opt, 72, 0x100000);          // stack reserve
    put64(opt, 80, 0x1000);            // stack commit
    put64(opt, 88, 0x100000);          // heap reserve
    put64(opt, 96, 0x1000);            // heap commit
    put32(opt, 108, 16);               // NumberOfRvaAndSizes
    put32(opt, 112, expRva);           // DataDirectory[0] export rva
    put32(opt, 116, expSize);          // DataDirectory[0] size

    auto sechdr = [&](const char* name, uint32_t vsize, uint32_t vaddr,
                      uint32_t rawsize, uint32_t rawptr, uint32_t chars) {
        Buf s;
        const size_t nlen = std::strlen(name);
        s.bytes(reinterpret_cast<const uint8_t*>(name), nlen);
        s.pad(8); // zero-pad the 8-byte name field
        s.u32(vsize); s.u32(vaddr); s.u32(rawsize); s.u32(rawptr);
        s.u32(0); s.u32(0); s.u16(0); s.u16(0); s.u32(chars);
        return s.b;
    };
    std::vector<uint8_t> secs;
    {
        auto t = sechdr(".text", 0x30, 0x1000, 0x30, 0x200, 0x60000020);
        secs.insert(secs.end(), t.begin(), t.end());
        t = sechdr(".rdata", 0x100, 0x2000, 0x100, 0x300, 0x40000040);
        secs.insert(secs.end(), t.begin(), t.end());
    }

    Buf out;
    out.u16(0x5A4D); // 'MZ'
    out.pad(0x3C);
    out.u32(0x40);   // e_lfanew
    out.pad(0x40);
    out.u8('P'); out.u8('E'); out.u8(0); out.u8(0);
    out.u16(0x8664); // machine AMD64
    out.u16(2);      // numberOfSections
    out.u32(0);      // timestamp
    out.u32(0);      // ptr symtab
    out.u32(0);      // num syms
    out.u16(240);    // size of optional header
    out.u16(0x22);   // characteristics
    out.bytes(opt.data(), opt.size());
    out.bytes(secs.data(), secs.size());
    out.pad(0x200);
    out.bytes(textV.data(), textV.size());
    out.pad(0x300);
    out.bytes(rdata.data(), rdata.size());
    return out.b;
}

bool writeFile(const char* path, const std::vector<uint8_t>& b) {
    FILE* f = std::fopen(path, "wb");
    if (!f) return false;
    const bool ok = std::fwrite(b.data(), 1, b.size(), f) == b.size();
    std::fclose(f);
    return ok;
}

} // namespace

int main(int argc, char** argv) {
    const char* dir = "samples";
    if (argc > 1) dir = argv[1];

    const std::string e64 = std::string(dir) + "/sample_elf64";
    const std::string e32 = std::string(dir) + "/sample_elf32";
    const std::string p64 = std::string(dir) + "/sample_pe64.exe";
    if (!writeFile(e64.c_str(), buildElf(true)) ||
        !writeFile(e32.c_str(), buildElf(false)) ||
        !writeFile(p64.c_str(), buildPe64())) {
        std::fprintf(stderr, "make_samples: failed to write samples\n");
        return 1;
    }
    std::printf("wrote %s, %s, %s\n", e64.c_str(), e32.c_str(), p64.c_str());
    return 0;
}
