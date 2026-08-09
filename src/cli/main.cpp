// ghra - a Ghidra reimplementation in C++17
// main.cpp - command-line front end
//
//   ghra <file> info
//   ghra <file> funcs
//   ghra <file> disasm <addr> [count]
//   ghra <file> dump <addr> <size>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ghra/analysis.hpp"
#include "ghra/disasm.hpp"
#include "ghra/loader.hpp"
#include "ghra/pcode.hpp"
#include "ghra/sleigh.hpp"

using namespace ghra;

namespace {

std::string hexAddr(uint64_t a) {
    char buf[24];
    if (a < 0x100000000ULL)
        std::snprintf(buf, sizeof(buf), "0x%08llX",
                      static_cast<unsigned long long>(a));
    else
        std::snprintf(buf, sizeof(buf), "0x%016llX",
                      static_cast<unsigned long long>(a));
    return buf;
}

bool parseAddr(const char* s, uint64_t& out) {
    if (!s || !*s) return false;
    char* end = nullptr;
    out = std::strtoull(s, &end, 0);
    return end && *end == '\0';
}

std::string permsStr(int perm) {
    std::string s = "---";
    if (perm & static_cast<int>(Perm::R)) s[0] = 'r';
    if (perm & static_cast<int>(Perm::W)) s[1] = 'w';
    if (perm & static_cast<int>(Perm::X)) s[2] = 'x';
    return s;
}

std::string upper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

const char* srcName(Function::Src s) {
    switch (s) {
    case Function::SYMBOL: return "sym";
    case Function::EXPORT: return "export";
    case Function::ENTRY:  return "entry";
    case Function::SCAN:   return "scan";
    }
    return "?";
}

int cmdInfo(const Program& p) {
    std::printf("file:      %s\n", p.path.c_str());
    std::printf("format:    %s\n", p.format.c_str());
    std::printf("arch:      %s\n", p.arch.c_str());
    std::printf("entry:     %s\n", hexAddr(p.entryPoint).c_str());
    std::printf("imagebase: %s\n", hexAddr(p.imageBase).c_str());
    std::printf("sections:  %zu\n", p.sections.size());
    std::printf("%-16s %-18s %-10s %s\n", "name", "addr", "size", "perms");
    for (const auto& s : p.sections)
        std::printf("%-16s %-18s %-10llu %s\n", s.name.c_str(),
                    hexAddr(s.addr).c_str(),
                    static_cast<unsigned long long>(s.size),
                    permsStr(s.perm).c_str());
    std::printf("symbols:   %zu\n", p.symbols.size());
    return 0;
}

int cmdFuncs(const Program& p, Disassembler* disasm) {
    auto funcs = findFunctions(p, disasm);
    std::printf("backend:   %s\n", disasm ? disasm->backendName().c_str() : "none");
    std::printf("FUNCTIONS (%zu)\n", funcs.size());
    std::printf("%-24s %-18s %-10s %s\n", "name", "addr", "size", "src");
    for (const auto& f : funcs)
        std::printf("%-24s %-18s %-10llu %s\n", f.name.c_str(),
                    hexAddr(f.addr).c_str(),
                    static_cast<unsigned long long>(f.size),
                    srcName(f.src));
    return 0;
}

int cmdDisasm(const Program& p, Disassembler& disasm, uint64_t addr,
              uint64_t count) {
    std::printf("; disassembling %s (backend: %s)\n", hexAddr(addr).c_str(),
                disasm.backendName().c_str());
    for (uint64_t i = 0; i < count; ++i) {
        Insn insn;
        if (!disasm.disasmOne(p.memory, addr, insn)) {
            std::printf("; undecodable at %s\n", hexAddr(addr).c_str());
            break;
        }
        std::string bytesHex;
        for (size_t b = 0; b < insn.bytes.size(); ++b) {
            char tmp[4];
            std::snprintf(tmp, sizeof(tmp), "%s%02x", b ? " " : "",
                          insn.bytes[b]);
            bytesHex += tmp;
        }
        std::string extra;
        if (insn.targetKnown) extra = "  ; -> " + hexAddr(insn.target);
        std::printf("%-18s %-24s %s%s\n", hexAddr(addr).c_str(),
                    bytesHex.c_str(), upper(insn.text).c_str(), extra.c_str());
        addr += insn.size;
    }
    return 0;
}

int cmdDump(const Program& p, uint64_t addr, uint64_t size) {
    uint8_t buf[16];
    for (uint64_t i = 0; i < size; i += 16) {
        size_t n = 0;
        for (; n < 16 && i + n < size; ++n) {
            if (!p.memory.read(addr + i + n, &buf[n], 1)) break;
        }
        if (n == 0) {
            std::printf("%-18s <unmapped>\n", hexAddr(addr + i).c_str());
            break;
        }
        std::string hex, ascii;
        for (size_t k = 0; k < 16; ++k) {
            if (k < n) {
                char t[4];
                std::snprintf(t, sizeof(t), "%02x ", buf[k]);
                hex += t;
                ascii += (buf[k] >= 0x20 && buf[k] < 0x7f)
                             ? static_cast<char>(buf[k])
                             : '.';
            } else {
                hex += "   ";
            }
        }
        std::printf("%-18s %s |%s|\n", hexAddr(addr + i).c_str(), hex.c_str(),
                    ascii.c_str());
    }
    return 0;
}

void usage(const char* argv0) {
    std::printf("usage:\n");
    std::printf("  %s <file> info\n", argv0);
    std::printf("  %s <file> funcs\n", argv0);
    std::printf("  %s <file> disasm <addr> [count]\n", argv0);
    std::printf("  %s <file> dump <addr> <size>\n", argv0);
    std::printf("  %s spec <spec.slaspec> <file> disasm <addr> [count]\n",
                argv0);
    std::printf("  %s spec <spec.slaspec> <file> funcs\n", argv0);
    std::printf("  %s spec <spec.slaspec> <file> pcode <addr> [count]\n",
                argv0);
}

std::shared_ptr<SleighEngine> loadSpecEngine(const char* path) {
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "ghra: cannot open spec: %s\n", path);
        return nullptr;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    auto eng = std::make_shared<SleighEngine>();
    std::string err;
    if (!eng->loadSpec(ss.str(), err)) {
        std::fprintf(stderr, "ghra: spec error: %s\n", err.c_str());
        return nullptr;
    }
    return eng;
}

int cmdPcode(const SleighEngine& eng, const Program& p, uint64_t addr,
             uint64_t count) {
    auto read = [&](uint64_t a, void* buf, size_t n) {
        return p.memory.read(a, buf, n);
    };
    for (uint64_t i = 0; i < count; ++i) {
        PcodeInsn pi;
        std::string err;
        if (!eng.disassemble(read, addr, pi, err)) {
            std::printf("; undecodable at %s\n", hexAddr(addr).c_str());
            break;
        }
        std::printf("%s: %s\n", hexAddr(addr).c_str(), pi.text.c_str());
        for (const auto& op : pi.ops) {
            std::string s = pOpName(op.op);
            s += " ";
            if (op.out) s += pi.varnodeName(op.out);
            if (op.in0) s += std::string(", ") + pi.varnodeName(op.in0);
            if (op.in1) s += std::string(", ") + pi.varnodeName(op.in1);
            if (op.in2) s += std::string(", ") + pi.varnodeName(op.in2);
            std::printf("    %s\n", s.c_str());
        }
        addr += pi.size;
    }
    return 0;
}

int cmdSpec(int argc, char** argv) {
    // argv[2]=spec argv[3]=binary argv[4]=cmd ...
    auto eng = loadSpecEngine(argv[2]);
    if (!eng) return 1;
    std::string err;
    auto prog = loadFile(argv[3], err);
    if (!prog) {
        std::fprintf(stderr, "ghra: %s\n", err.c_str());
        return 1;
    }
    const std::string cmd = argv[4];
    if (cmd == "funcs") {
        SpecDisassembler d(eng);
        return cmdFuncs(*prog, &d);
    }
    if (cmd == "disasm") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0, count = 16;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "ghra: bad address '%s'\n", argv[5]);
            return 1;
        }
        if (argc >= 7) count = std::strtoull(argv[6], nullptr, 0);
        SpecDisassembler d(eng);
        return cmdDisasm(*prog, d, addr, count);
    }
    if (cmd == "pcode") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0, count = 8;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "ghra: bad address '%s'\n", argv[5]);
            return 1;
        }
        if (argc >= 7) count = std::strtoull(argv[6], nullptr, 0);
        return cmdPcode(*eng, *prog, addr, count);
    }
    usage(argv[0]);
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }
    const std::string path = argv[1];
    const std::string cmd = argv[2];

    if (path == "spec") return cmdSpec(argc, argv);

    std::string err;
    auto prog = loadFile(path, err);
    if (!prog) {
        std::fprintf(stderr, "ghra: %s\n", err.c_str());
        return 1;
    }

    if (cmd == "info") return cmdInfo(*prog);

    if (cmd == "funcs") {
        auto disasm = makeDisassembler(prog->arch);
        return cmdFuncs(*prog, disasm.get());
    }

    if (cmd == "disasm") {
        if (argc < 4) { usage(argv[0]); return 1; }
        uint64_t addr = 0, count = 16;
        if (!parseAddr(argv[3], addr)) {
            std::fprintf(stderr, "ghra: bad address '%s'\n", argv[3]);
            return 1;
        }
        if (argc >= 5) count = std::strtoull(argv[4], nullptr, 0);
        auto disasm = makeDisassembler(prog->arch);
        return cmdDisasm(*prog, *disasm, addr, count);
    }

    if (cmd == "dump") {
        if (argc < 5) { usage(argv[0]); return 1; }
        uint64_t addr = 0, size = 64;
        if (!parseAddr(argv[3], addr)) {
            std::fprintf(stderr, "ghra: bad address '%s'\n", argv[3]);
            return 1;
        }
        size = std::strtoull(argv[4], nullptr, 0);
        return cmdDump(*prog, addr, size);
    }

    usage(argv[0]);
    return 1;
}
