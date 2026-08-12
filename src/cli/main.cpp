// centrifuge - a Ghidra reimplementation in C++17
// main.cpp - command-line front end
//
//   centrifuge <file> info
//   centrifuge <file> funcs
//   centrifuge <file> disasm <addr> [count]
//   centrifuge <file> dump <addr> <size>
#include <cctype>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/analysis.hpp"
#include "centrifuge/cfg.hpp"
#include "centrifuge/decompile.hpp"
#include "centrifuge/disasm.hpp"
#include "centrifuge/loader.hpp"
#include "centrifuge/ir.hpp"
#include "centrifuge/highir.hpp"
#include "centrifuge/pcode.hpp"
#include "centrifuge/program_graph.hpp"
#include "centrifuge/project_recovery.hpp"
#include "centrifuge/sleigh.hpp"
#include "centrifuge/semantic_coverage.hpp"
#include "centrifuge/stack_recovery.hpp"

using namespace centrifuge;

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

const char* modRefName(ModRefInfo info) {
    switch (info) {
    case ModRefInfo::NO_ACCESS: return "none";
    case ModRefInfo::REF: return "ref";
    case ModRefInfo::MOD: return "mod";
    case ModRefInfo::MOD_REF: return "mod/ref";
    case ModRefInfo::UNKNOWN: return "unknown";
    }
    return "unknown";
}

const char* cppMethodRoleName(CppMethodRole role) {
    switch (role) {
    case CppMethodRole::UNKNOWN: return "unknown";
    case CppMethodRole::METHOD: return "method";
    case CppMethodRole::CONSTRUCTOR: return "constructor";
    case CppMethodRole::COPY_CONSTRUCTOR: return "copy-constructor";
    case CppMethodRole::MOVE_CONSTRUCTOR: return "move-constructor";
    case CppMethodRole::BASE_DESTRUCTOR: return "base-destructor";
    case CppMethodRole::COMPLETE_DESTRUCTOR: return "complete-destructor";
    case CppMethodRole::DELETING_DESTRUCTOR: return "deleting-destructor";
    case CppMethodRole::COPY_ASSIGNMENT: return "copy-assignment";
    case CppMethodRole::MOVE_ASSIGNMENT: return "move-assignment";
    case CppMethodRole::VIRTUAL_METHOD: return "virtual-method";
    case CppMethodRole::PURE_VIRTUAL: return "pure-virtual";
    case CppMethodRole::ADJUSTOR_THUNK: return "adjustor-thunk";
    case CppMethodRole::COVARIANT_RETURN_THUNK: return "covariant-return-thunk";
    case CppMethodRole::FACTORY: return "factory";
    case CppMethodRole::ALLOCATOR: return "allocator";
    case CppMethodRole::DEALLOCATOR: return "deallocator";
    }
    return "unknown";
}

const char* cppRuntimeOperationName(CppRuntimeOperationKind kind) {
    switch (kind) {
    case CppRuntimeOperationKind::DYNAMIC_CAST: return "dynamic_cast";
    case CppRuntimeOperationKind::TYPEID: return "typeid";
    case CppRuntimeOperationKind::THROW_EXCEPTION: return "throw";
    case CppRuntimeOperationKind::BEGIN_CATCH: return "begin-catch";
    case CppRuntimeOperationKind::END_CATCH: return "end-catch";
    case CppRuntimeOperationKind::RETHROW: return "rethrow";
    case CppRuntimeOperationKind::PLACEMENT_NEW: return "placement-new";
    }
    return "runtime-operation";
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
    case Function::UNWIND: return "unwind";
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
    std::printf("imports:   %zu symbols from %zu DLLs\n", p.imports.size(),
                p.importedLibraries.size());
    std::printf("data:      %zu non-executable regions\n", p.dataRegions.size());
    std::printf("resources: %zu leaves\n", p.resources.size());
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
    std::printf("  %s spec <spec.slaspec> <file> cfg <addr> [end]\n", argv0);
    std::printf("  %s spec <spec.slaspec> <file> analyze <addr> [end] [abi]\n",
                argv0);
    std::printf("  %s spec <spec.slaspec> <file> midir <addr> [end] [abi]\n",
                argv0);
    std::printf("  %s spec <spec.slaspec> <file> highir <addr> [end]\n",
                argv0);
    std::printf("  %s spec <spec.slaspec> <file> analyze-all [abi]\n", argv0);
    std::printf("  %s spec <spec.slaspec> <file> cpp-types\n", argv0);
    std::printf("  %s spec <spec.slaspec> <file> knowledge-graph [output.json] [abi]\n",
                argv0);
    std::printf("  %s spec <spec.slaspec> <file> recover-project <output-dir> "
                "[abi] [max-functions]\n", argv0);
    std::printf("  %s spec <spec.slaspec> <file> semantic-coverage\n", argv0);
    std::printf("  %s spec <spec.slaspec> <file> decompile-typed <addr> [abi]\n",
                argv0);
    std::printf("  %s spec <spec.slaspec> <file> decompile-native <addr> [end] [abi]\n",
                argv0);
    std::printf("  %s spec <spec.slaspec> <file> decompile <addr> [end]\n",
                argv0);
}

std::shared_ptr<SleighEngine> loadSpecEngine(const char* path) {
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "centrifuge: cannot open spec: %s\n", path);
        return nullptr;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    auto eng = std::make_shared<SleighEngine>();
    std::string err;
    if (!eng->loadSpec(ss.str(), err)) {
        std::fprintf(stderr, "centrifuge: spec error: %s\n", err.c_str());
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
        std::fprintf(stderr, "centrifuge: %s\n", err.c_str());
        return 1;
    }
    auto reader = [&](uint64_t a, void* buf, size_t n) {
        return prog->memory.read(a, buf, n);
    };
    const std::string cmd = argv[4];
    if (cmd == "funcs") {
        SpecDisassembler d(eng);
        return cmdFuncs(*prog, &d);
    }
    if (cmd == "disasm") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0, count = 16;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[5]);
            return 1;
        }
        if (argc >= 7) count = std::strtoull(argv[6], nullptr, 0);
        SpecDisassembler d(eng);
        if (argc >= 8 && std::string(argv[7]) == "--resume") {
            // coverage scanning: skip undecodable bytes and continue
            for (uint64_t i = 0; i < count; ++i) {
                Insn insn;
                if (!d.disasmOne(prog->memory, addr, insn)) {
                    std::printf("; GAP %s\n", hexAddr(addr).c_str());
                    addr++;
                    continue;
                }
                std::string bytesHex;
                for (size_t b = 0; b < insn.bytes.size(); ++b) {
                    char tmp[4];
                    std::snprintf(tmp, sizeof(tmp), "%s%02x", b ? " " : "",
                                  insn.bytes[b]);
                    bytesHex += tmp;
                }
                std::printf("%s %s %s\n", hexAddr(addr).c_str(),
                            bytesHex.c_str(), insn.text.c_str());
                addr += insn.size;
            }
            return 0;
        }
        return cmdDisasm(*prog, d, addr, count);
    }
    if (cmd == "pcode") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0, count = 8;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[5]);
            return 1;
        }
        if (argc >= 7) count = std::strtoull(argv[6], nullptr, 0);
        return cmdPcode(*eng, *prog, addr, count);
    }
    if (cmd == "cfg") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[5]);
            return 1;
        }
        uint64_t end = 0;
        if (argc >= 7) end = std::strtoull(argv[6], nullptr, 0);
        CfgBuilder cfg;
        auto executable = [&](uint64_t target) {
            return prog->memory.isExecutable(target);
        };
        if (!cfg.build(*eng, reader, addr, end, executable)) {
            std::fprintf(stderr, "centrifuge: cfg build failed\n");
            return 1;
        }
        for (const auto& b : cfg.blocks()) {
            std::printf("0x%llx (end 0x%llx, %zu insns):",
                        static_cast<unsigned long long>(b.start),
                        static_cast<unsigned long long>(b.end), b.insns.size());
            for (uint64_t s : b.succs)
                std::printf(" -> 0x%llx",
                            static_cast<unsigned long long>(s));
            for (uint64_t target : b.calls)
                std::printf(" call 0x%llx",
                            static_cast<unsigned long long>(target));
            if (b.tailCallTarget)
                std::printf(" tail 0x%llx",
                            static_cast<unsigned long long>(*b.tailCallTarget));
            std::printf("\n");
        }
        for (const auto& loop : cfg.loops()) {
            std::printf("loop 0x%llx (%zu blocks, %zu exits)",
                        static_cast<unsigned long long>(loop.header),
                        loop.blocks.size(), loop.exits.size());
            if (loop.parentHeader)
                std::printf(" parent 0x%llx",
                            static_cast<unsigned long long>(*loop.parentHeader));
            std::printf("\n");
        }
        std::printf("dominators(entry):");
        for (uint64_t d : cfg.dominators(addr))
            std::printf(" 0x%llx", static_cast<unsigned long long>(d));
        std::printf("\n");
        return 0;
    }
    if (cmd == "highir") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0, end = 0;
        if (!parseAddr(argv[5], addr) ||
            (argc >= 7 && !parseAddr(argv[6], end))) {
            std::fprintf(stderr, "centrifuge: bad HighIR address range\n");
            return 1;
        }
        CfgBuilder cfg;
        auto executable = [&](uint64_t target) {
            return prog->memory.isExecutable(target);
        };
        if (!cfg.build(*eng, reader, addr, end, executable)) {
            std::fprintf(stderr, "centrifuge: CFG construction failed\n");
            return 1;
        }
        cfg.applyExceptionRegions(prog->exceptionRegions);
        const int pointerSize = prog->arch == "x86" ? 4 : 8;
        const std::vector<JumpTable> tables =
            recoverJumpTables(cfg, prog->memory, pointerSize);
        const HighFunction high = HighIRBuilder().build(cfg, tables);
        std::printf("highir: %zu structured nodes, %zu irreducible regions\n",
                    high.structuredNodes, high.irreducibleRegions.size());
        std::printf("%s", high.dump().c_str());
        return 0;
    }
    if (cmd == "analyze" || cmd == "midir") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[5]);
            return 1;
        }
        uint64_t end = 0;
        if (argc >= 7 && !parseAddr(argv[6], end)) {
            std::fprintf(stderr, "centrifuge: bad end address '%s'\n", argv[6]);
            return 1;
        }
        const std::string abi = argc >= 8 ? argv[7] : std::string();
        CfgBuilder cfg;
        auto executable = [&](uint64_t target) {
            return prog->memory.isExecutable(target);
        };
        if (!cfg.build(*eng, reader, addr, end, executable)) {
            std::fprintf(stderr, "centrifuge: cfg build failed\n");
            return 1;
        }
        cfg.applyExceptionRegions(prog->exceptionRegions);
        FunctionIR ir;
        if (!ir.build(cfg, prog->arch, abi)) {
            std::fprintf(stderr, "centrifuge: MidIR construction failed\n");
            return 1;
        }
        ir.inferTypes();
        const FunctionSignature signature = ir.inferSignature();
        ir.optimize();
        std::string functionName = "FUN_" + hexAddr(addr).substr(2);
        for (const auto& symbol : prog->symbols)
            if (symbol.isFunction && symbol.addr == addr) {
                functionName = symbol.name;
                break;
            }
        std::printf("signature: %s\n", signature.declaration(functionName).c_str());
        const MidIRVerification verification = ir.verify();
        std::printf("midir: %zu blocks, %zu phi nodes, %zu live operations, "
                    "%zu memory partitions, %s\n",
                    ir.blocks().size(), ir.phiCount(), ir.liveOpCount(),
                    ir.memoryPartitions().size(),
                    verification.valid() ? "verified" : "invalid");
        const int pointerSize = prog->arch == "x86" ? 4 : 8;
        for (const JumpTable& table : recoverJumpTables(cfg, prog->memory,
                                                        pointerSize)) {
            std::printf("jump-table 0x%llx at 0x%llx (%zu targets%s)\n",
                        static_cast<unsigned long long>(table.dispatchAddress),
                        static_cast<unsigned long long>(table.tableAddress),
                        table.targets.size(), table.relative ? ", relative" : "");
        }
        std::printf("%s", ir.dump().c_str());
        return 0;
    }
    if (cmd == "analyze-all") {
        const std::string abi = argc >= 6 ? argv[5] : std::string();
        ProgramAnalysis analysis;
        if (!analysis.build(*prog, *eng, abi)) {
            std::fprintf(stderr, "centrifuge: program analysis failed\n");
            return 1;
        }
        for (const auto& entry : analysis.functions()) {
            const AnalyzedFunction& function = entry.second;
            std::printf("%s @ %s%s%s\n",
                        function.signature.declaration(function.function.name).c_str(),
                        hexAddr(function.function.addr).c_str(),
                        function.complete ? "" : " [incomplete]",
                        function.complexityLimited ? " [complexity-limited]" : "");
            std::printf("  cfg=%zu phi=%zu ops=%zu callers=%zu callees=%zu "
                        "modref=%s%s%s\n",
                        function.blocks, function.phiNodes,
                        function.liveOperations, function.callers.size(),
                        function.callees.size(),
                        modRefName(function.effects.modRef()),
                        function.effects.allocates ? " allocates" : "",
                        function.effects.frees ? " frees" : "");
            for (uint64_t target : function.callees)
                std::printf("  -> %s\n", hexAddr(target).c_str());
        }
        return 0;
    }
    if (cmd == "knowledge-graph") {
        const std::string abi = argc >= 7 ? argv[6] : std::string();
        ProgramAnalysis analysis;
        if (!analysis.build(*prog, *eng, abi)) {
            std::fprintf(stderr, "centrifuge: program analysis failed\n");
            return 1;
        }
        const ProgramKnowledgeGraph graph =
            buildProgramKnowledgeGraph(*prog, analysis);
        const std::string json = graph.toJson();
        if (argc >= 6) {
            std::ofstream output(argv[5], std::ios::binary | std::ios::trunc);
            if (!output) {
                std::fprintf(stderr, "centrifuge: cannot create graph: %s\n",
                             argv[5]);
                return 1;
            }
            output << json;
            if (!output) {
                std::fprintf(stderr, "centrifuge: cannot write graph: %s\n",
                             argv[5]);
                return 1;
            }
            std::printf("knowledge graph: %zu nodes, %zu edges -> %s\n",
                        graph.nodes().size(), graph.edges().size(), argv[5]);
        } else {
            std::printf("%s", json.c_str());
        }
        return 0;
    }
    if (cmd == "recover-project") {
        if (argc < 6) { usage(argv[0]); return 1; }
        ProjectRecoveryOptions options;
        options.outputDirectory = argv[5];
        options.callingConvention = argc >= 7 ? argv[6] : std::string();
        if (argc >= 8)
            options.maximumFunctions = static_cast<size_t>(
                std::strtoull(argv[7], nullptr, 0));
        ProgramAnalysis analysis;
        if (!analysis.build(*prog, *eng, options.callingConvention,
                            options.maximumFunctions)) {
            std::fprintf(stderr, "centrifuge: program analysis failed\n");
            return 1;
        }
        ProjectRecoveryReport report;
        std::string recoveryError;
        if (!recoverSourceProject(*prog, *eng, analysis, options, report,
                                  recoveryError)) {
            std::fprintf(stderr, "centrifuge: project recovery failed: %s\n",
                         recoveryError.c_str());
            return 1;
        }
        std::printf("recovered project: %zu/%zu functions (%zu decompiled, "
                    "%zu stubs, %zu complexity-limited), %zu source files, "
                    "%zu unresolved markers, "
                    "%zu imports from %zu DLLs, %zu data regions, %zu "
                    "image regions (%llu bytes), %zu resources, entry %s "
                    "(%s), %zu knowledge nodes, %zu "
                    "edges -> %s\n",
                    report.emittedFunctions, report.discoveredFunctions,
                    report.decompiledFunctions, report.stubbedFunctions,
                    report.complexityLimitedFunctions, report.sourceFiles,
                    report.unresolvedMarkers,
                    report.importedSymbols, report.importedLibraries,
                    report.dataRegions, report.imageRegions,
                    static_cast<unsigned long long>(report.imageBytes),
                    report.resources,
                    hexAddr(report.entryPoint).c_str(),
                    report.entryPointRecovered ? "recovered" : "missing",
                    report.knowledgeNodes, report.knowledgeEdges,
                    options.outputDirectory.c_str());
        return 0;
    }
    if (cmd == "cpp-types") {
        CppRecoveryResult recovered = recoverCppTypes(*prog);
        ProgramAnalysis analysis;
        if (analysis.build(*prog, *eng)) recovered = analysis.cppTypes();
        for (const CppClassInfo& type : recovered.classes) {
            std::printf("class %s [%s] identity=%s typeinfo=%s vtable=%s "
                        "size=%llu align=%llu confidence=%.2f%s%s\n",
                        type.name.c_str(),
                        type.abi == CppAbi::ITANIUM ? "itanium" : "msvc",
                        type.stableIdentity.c_str(),
                        hexAddr(type.typeInfoAddress).c_str(),
                        hexAddr(type.vtableAddress).c_str(),
                        static_cast<unsigned long long>(type.inferredSize),
                        static_cast<unsigned long long>(type.inferredAlignment),
                        type.confidence, type.isAbstract ? " abstract" : "",
                        type.hasVirtualInheritance
                            ? " virtual-inheritance" : "");
            if (!type.libraryPattern.empty())
                std::printf("  library-pattern %s\n",
                            type.libraryPattern.c_str());
            for (const CppBaseClass& base : type.bases)
                std::printf("  base %s offset=%lld%s\n", base.name.c_str(),
                            static_cast<long long>(base.byteOffset),
                            base.isVirtual ? " virtual" : "");
            for (const CppVirtualFunction& function : type.virtualFunctions)
                std::printf("  vfunc[%zu] %s @ %s\n", function.slot,
                            function.name.c_str(),
                            hexAddr(function.address).c_str());
            for (const CppFieldInfo& field : type.fields)
                std::printf("  field %+lld size=%llu %s%s%s%s confidence=%.2f\n",
                            static_cast<long long>(field.byteOffset),
                            static_cast<unsigned long long>(field.byteSize),
                            field.name.c_str(), field.isVptr ? " [vptr]" : "",
                            field.isVbptr ? " [vbptr]" : "",
                            field.isBaseSubobject ? " [base]" : "",
                            field.confidence);
            for (const CppMethodInfo& method : type.methods)
                std::printf("  method %s @ %s role=%s this-adjust=%lld%s "
                            "confidence=%.2f\n",
                            method.name.c_str(), hexAddr(method.address).c_str(),
                            cppMethodRoleName(method.role),
                            static_cast<long long>(method.thisAdjustment),
                            method.isVirtual ? " virtual" : "",
                            method.confidence);
        }
        for (const CppVptrWrite& write : recovered.objectGraph.vptrWrites)
            std::printf("vptr-write %s %+lld <- %s in %s confidence=%.2f\n",
                        write.className.c_str(),
                        static_cast<long long>(write.objectOffset),
                        hexAddr(write.vtableAddress).c_str(),
                        hexAddr(write.functionAddress).c_str(), write.confidence);
        for (const CppVirtualCallSite& call :
             recovered.objectGraph.virtualCalls)
            std::printf("virtual-call %s slot=%zu vptr=%+lld at %s target=%s "
                        "confidence=%.2f\n",
                        call.className.c_str(), call.slot,
                        static_cast<long long>(call.vptrOffset),
                        hexAddr(call.instructionAddress).c_str(),
                        hexAddr(call.resolvedTarget).c_str(), call.confidence);
        for (const CppRuntimeOperation& operation :
             recovered.objectGraph.runtimeOperations)
            std::printf("runtime %s in %s class=%s type=%s landing-pad=%s "
                        "action=%lld confidence=%.2f\n",
                        cppRuntimeOperationName(operation.kind),
                        hexAddr(operation.functionAddress).c_str(),
                        operation.className.c_str(),
                        operation.referencedType.c_str(),
                        hexAddr(operation.landingPad).c_str(),
                        static_cast<long long>(operation.action),
                        operation.confidence);
        for (const CppObjectCandidate& object : recovered.objectGraph.objects)
            std::printf("object #%llu class=%s size=%llu allocation=%s%s "
                        "events=%zu confidence=%.2f\n",
                        static_cast<unsigned long long>(object.id),
                        object.className.c_str(),
                        static_cast<unsigned long long>(object.inferredSize),
                        hexAddr(object.allocationSite).c_str(),
                        object.placementNew ? " placement-new" : "",
                        object.lifetime.size(), object.confidence);
        return 0;
    }
    if (cmd == "semantic-coverage") {
        const SemanticCoverageReport coverage =
            auditSemanticCoverage(*prog, *eng);
        const ConstructorProofReport proofs = auditConstructorProof(*eng);
        std::printf("semantic coverage: %.2f%% bytes (%zu instructions, "
                    "%zu decode failures, %zu empty semantics, "
                    "%zu unimplemented operations)\n",
                    coverage.byteCoverage() * 100.0, coverage.instructions,
                    coverage.decodeFailures, coverage.emptySemantics,
                    coverage.unimplementedOperations);
        for (const auto& missing : coverage.missingByMnemonic)
            std::printf("  missing %-16s %zu\n", missing.first.c_str(),
                        missing.second);
        std::printf("constructor proof inventory: %zu total, %zu inline, "
                    "%zu verified shared, %zu unproven\n",
                    proofs.constructors, proofs.inlineSpecifications,
                    proofs.sharedSpecifications, proofs.unproven);
        std::vector<std::pair<std::string, size_t>> unproven(
            proofs.unprovenByMnemonic.begin(),
            proofs.unprovenByMnemonic.end());
        std::sort(unproven.begin(), unproven.end(),
                  [](const auto& left, const auto& right) {
                      return left.second != right.second
                                 ? left.second > right.second
                                 : left.first < right.first;
                  });
        for (size_t index = 0; index < unproven.size(); ++index)
            std::printf("  unproven %-16s %zu constructors\n",
                        unproven[index].first.c_str(), unproven[index].second);
        // Keep the command usable as an inventory on partially specified
        // architectures.  CI/baseline policy decides whether nonzero empty
        // semantics is acceptable; explicit UNIMPLEMENTED is always fatal.
        return coverage.unimplementedOperations ? 2 : 0;
    }
    if (cmd == "decompile-typed") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[5]);
            return 1;
        }
        const std::string abi = argc >= 7 ? argv[6] : std::string();
        ProgramAnalysis analysis;
        if (!analysis.build(*prog, *eng, abi)) {
            std::fprintf(stderr, "centrifuge: program analysis failed\n");
            return 1;
        }
        if (!analysis.functionAt(addr)) {
            std::fprintf(stderr, "centrifuge: function %s was not discovered\n",
                         hexAddr(addr).c_str());
            return 1;
        }
        std::printf("%s", analysis.decompileFunction(*prog, *eng, addr).c_str());
        return 0;
    }
    if (cmd == "decompile-native") {
        // Native Source Recovery Backend: StackFrameAnalysis drives stack
        // slot promotion; stable locals become typed variables instead of
        // raw rsp/rbp memory expressions.
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[5]);
            return 1;
        }
        uint64_t end = 0;
        if (argc >= 7) end = std::strtoull(argv[6], nullptr, 0);
        if (end == 0) end = addr + 0x1000;
        CfgBuilder cfg;
        if (!cfg.build(*eng, reader, addr, end)) {
            std::fprintf(stderr, "centrifuge: failed to build CFG\n");
            return 1;
        }
        const std::string abi = argc >= 8 ? argv[7] : std::string();
        const std::string arch = prog->arch + abi;
        StackFrameAnalysis analysis;
        analysis.analyze(cfg, arch);
        const StackFrameModel& model = analysis.model();
        std::printf("// stack frame: size=0x%llx frame_pointer=%s "
                    "slots=%zu promoted=%zu\n",
                    (unsigned long long)model.frameSize,
                    model.hasFramePointer ? "yes" : "no",
                    model.slots.size(), model.promotedCount);
        auto nameOf = [&](uint64_t target) -> std::string {
            for (const auto& s : prog->symbols)
                if (s.isFunction && s.addr == target) return s.name;
            char buf[24];
            std::snprintf(buf, sizeof(buf), "FUN_%llx",
                          static_cast<unsigned long long>(target));
            return buf;
        };
        std::printf("%s", decompile(*eng, reader, addr, end, nameOf, nullptr,
                                     arch, false, &model).c_str());
        return 0;
    }
    if (cmd == "decompile") {
        if (argc < 6) { usage(argv[0]); return 1; }
        uint64_t addr = 0;
        if (!parseAddr(argv[5], addr)) {
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[5]);
            return 1;
        }
        uint64_t end = 0;
        if (argc >= 7) end = std::strtoull(argv[6], nullptr, 0);
        auto nameOf = [&](uint64_t target) -> std::string {
            for (const auto& s : prog->symbols)
                if (s.isFunction && s.addr == target) return s.name;
            char buf[24];
            std::snprintf(buf, sizeof(buf), "FUN_%llx",
                          static_cast<unsigned long long>(target));
            return buf;
        };
        std::printf("%s", decompile(*eng, reader, addr, end, nameOf, nullptr,
                                     prog->arch).c_str());
        return 0;
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
        std::fprintf(stderr, "centrifuge: %s\n", err.c_str());
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
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[3]);
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
            std::fprintf(stderr, "centrifuge: bad address '%s'\n", argv[3]);
            return 1;
        }
        size = std::strtoull(argv[4], nullptr, 0);
        return cmdDump(*prog, addr, size);
    }

    usage(argv[0]);
    return 1;
}
