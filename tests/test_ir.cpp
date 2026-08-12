// Function-level SSA, type, ABI, optimizer, and jump-table tests.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "centrifuge/ir.hpp"
#include "centrifuge/highir.hpp"
#include "centrifuge/cpp_recovery.hpp"
#include "centrifuge/decompile.hpp"
#include "centrifuge/program_graph.hpp"
#include "centrifuge/sleigh.hpp"
#include "centrifuge/import_prototype.hpp"

using namespace centrifuge;

namespace {
int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++failures; } } while (0)

const char* miniSpec = R"SPEC(
define space ram size=8 type=ram_space default;
define space regs size=8 type=register_space;
define register offset=0 size=8 [ r0 r1 ];
token t8 (1) { op = (7:0); }
:br is op=1 { if (r0 != 0) goto inst_start + 2; };
:left is op=2 { r1 = 10; goto inst_start + 2; };
:right is op=3 { r1 = 20; };
:join is op=4 { r0 = r1 + 0; return; };
:indirect is op=5 { target = load(0x100, 8); goto target; };
:ret is op=6 { return; };
:invoke is op=7 { call 8; };
:aggregate is op=9 { p0 = r0 + 0; a = load(p0, 8); p1 = r0 + 8; b = load(p1, 8); p2 = r0 + 16; c = load(p2, 8); r1 = a + b; r1 = r1 + c; return; };
:invoke_indirect is op=10 { call r0; return; };
:noalias_load is op=11 { p0 = r0 + 0; a = load(p0, 8); p1 = r0 + 16; *(p1) = r1; b = load(p0, 8); r1 = a + b; return; };
:mayalias_load is op=12 { p0 = r0 + 0; a = load(p0, 8); *(r1) = a; b = load(p0, 8); r0 = b; return; };
:invoke_reader is op=13 { call 12; return; };
:heap_global is op=14 { a = load(r0, 8); b = load(0x100, 8); r1 = a + b; return; };
:object_ctor is op=15 { *(r1) = 0x100; p0 = r1 + 8; *(p0) = r0; return; };
:virtual_invoke is op=16 { vptr = load(r1, 8); fn = load(vptr, 8); call fn; return; };
:member_caller is op=17 { call 0x24; return; };
:runtime_cast is op=18 { call 0x25; return; };
:placement_factory is op=19 { call 0x27; call 0x20; return; };
:invoke_leaf is op=20 { call 20; return; };
:tail_forward is op=21 { goto 0x40; };
:zero_and is op=22 { r1 = r0 & 0; return; };
:parallel_outputs is op=23 { lo = r0 + 1; hi = r0 + 2; r0 = lo; r1 = hi; return; };
)SPEC";

const char* mixedWidthAbiSpec = R"SPEC(
define space ram size=8 type=ram_space default;
define space regs size=8 type=register_space;
define register offset=0 size=8 [ rax ];
define register offset=0 size=4 [ eax ];
define register offset=0 size=2 [ ax ];
define register offset=0 size=1 [ al ];
define register offset=1 size=1 [ ah ];
define register offset=8 size=8 [ rcx ];
define register offset=8 size=4 [ ecx ];
token t8 (1) { op = (7:0); }
:mixed is op=1 { p = rcx + 248; wide = load(p, 8); narrow = ecx + 1; rax = wide + narrow; return; };
:narrow_read is op=2 { value = al & al; rcx = zext(value); return; };
:write_al is op=3 { al = 0x12; return; };
:write_ah is op=4 { ah = 0x34; return; };
:write_eax is op=5 { eax = 0xffffffff; return; };
)SPEC";

const char* stackEscapeSpec = R"SPEC(
define space ram size=8 type=ram_space default;
define space regs size=8 type=register_space;
define register offset=0 size=8 [ rax ];
define register offset=8 size=8 [ rcx ];
define register offset=16 size=8 [ rdx ];
define register offset=32 size=8 [ rsp ];
token t8 (1) { op = (7:0); }
:stack_escape is op=1 { rsp = rsp - 16; p = rsp + 8; *(p) = rcx; rdx = p; return; };
)SPEC";

const char* win64StackArgumentSpec = R"SPEC(
define space ram size=8 type=ram_space default;
define space regs size=8 type=register_space;
define register offset=0 size=8 [ rax ];
define register offset=8 size=8 [ rcx ];
define register offset=16 size=8 [ rdx ];
define register offset=32 size=8 [ rsp ];
token t8 (1) { op = (7:0); }
:stack_down is op=1 { rsp = rsp - 56; };
:load_argument is op=2 { p = rsp + 96; rax = load(p, 4); };
:stack_up_return is op=3 { rsp = rsp + 56; return; };
:store_argument is op=4 { p = rsp + 32; *(p) = 1; };
:call_callee is op=5 { call 0; };
)SPEC";
}

int main() {
    SleighEngine engine;
    std::string error;
    CHECK(engine.loadSpec(miniSpec, error), "load miniature SSA specification");

    std::vector<uint8_t> bytes(64, 6);
    bytes[0] = 1; bytes[1] = 2; bytes[2] = 3; bytes[3] = 4;
    auto read = [&](uint64_t address, void* out, size_t size) {
        if (address > bytes.size() || size > bytes.size() - address) return false;
        std::memcpy(out, bytes.data() + address, size); return true;
    };
    CfgBuilder cfg;
    CHECK(cfg.build(engine, read, 0, 4), "build diamond CFG");
    CHECK(cfg.blocks().size() == 4, "diamond contains four basic blocks");
    cfg.applyExceptionRegions({ExceptionRegion{ExceptionRegion::WINDOWS_UNWIND,
                                                0, 1, 0x200, 0x30, 0}});
    CHECK(!cfg.blocks().empty() && cfg.blocks()[0].exceptionSuccs ==
                                      std::vector<uint64_t>{0x30},
          "exception metadata creates a separate CFG edge");

    FunctionIR ir;
    CHECK(ir.build(cfg, "generic"), "construct function-level SSA");
    CHECK(!ir.blocks().empty() &&
              std::find(ir.blocks()[0].successors.begin(),
                        ir.blocks()[0].successors.end(), 0x30) !=
                  ir.blocks()[0].successors.end(),
          "SSA control flow preserves exceptional successors");
    CHECK(ir.phiCount() >= 2, "join block receives register phi nodes");
    const std::string before = ir.dump();
    CHECK(before.find("PHI") != std::string::npos, "SSA dump contains phi");

    const FunctionSignature signature = ir.inferSignature();
    CHECK(!signature.parameters.empty(), "ABI inference recovers live-in argument");
    CHECK(signature.parameters.size() == 1,
          "ABI inference excludes registers referenced only by dead phi nodes");
    CHECK(signature.returnType.kind != TypeKind::VOID_TYPE,
          "ABI inference recovers return value");
    CHECK(signature.declaration("diamond").find("arg0") != std::string::npos,
          "signature declaration names recovered argument");

    {
        const std::vector<uint8_t> zeroAndBytes{22};
        auto zeroAndRead = [&](uint64_t address, void* output, size_t size) {
            if (address > zeroAndBytes.size() ||
                size > zeroAndBytes.size() - address)
                return false;
            std::memcpy(output, zeroAndBytes.data() + address, size);
            return true;
        };
        const std::string zeroAndSource = decompile(
            engine, zeroAndRead, 0, 1, nullptr, nullptr, "generic");
        CHECK(zeroAndSource.find("r1 = 0;") != std::string::npos,
              "C lowering preserves x AND 0 as zero rather than x");
    }

    {
        const std::vector<uint8_t> parallelBytes{23};
        auto parallelRead = [&](uint64_t address, void* output, size_t size) {
            if (address > parallelBytes.size() ||
                size > parallelBytes.size() - address)
                return false;
            std::memcpy(output, parallelBytes.data() + address, size);
            return true;
        };
        const std::string parallelSource = decompile(
            engine, parallelRead, 0, 1, nullptr, nullptr, "generic");
        CHECK(parallelSource.find("const auto recovered_old_0_r0 = r0;") !=
                  std::string::npos &&
              parallelSource.find("r1 = recovered_old_0_r0 + 2;") !=
                  std::string::npos,
              "C lowering snapshots an earlier parallel register output");
    }

    {
        SleighEngine mixedWidthEngine;
        std::string mixedWidthError;
        CHECK(mixedWidthEngine.loadSpec(mixedWidthAbiSpec, mixedWidthError),
              "load overlapping x86 ABI register-view specification");
        const std::vector<uint8_t> mixedWidthBytes{1};
        auto mixedWidthRead = [&](uint64_t address, void* output, size_t size) {
            if (address > mixedWidthBytes.size() ||
                size > mixedWidthBytes.size() - address)
                return false;
            std::memcpy(output, mixedWidthBytes.data() + address, size);
            return true;
        };
        CfgBuilder mixedWidthCfg;
        CHECK(mixedWidthCfg.build(mixedWidthEngine, mixedWidthRead, 0, 1),
              "build mixed-width x86 ABI function");
        FunctionIR mixedWidthIr;
        CHECK(mixedWidthIr.build(mixedWidthCfg, "x86-64", "win64"),
              "construct mixed-width x86 ABI SSA");
        const FunctionSignature mixedWidthSignature =
            mixedWidthIr.inferSignature();
        CHECK(mixedWidthSignature.parameters.size() == 1 &&
                  mixedWidthSignature.parameters[0].registerOffset == 8 &&
                  mixedWidthSignature.parameters[0].type.kind ==
                      TypeKind::POINTER &&
                  mixedWidthSignature.parameters[0].type.bits == 64,
              "merge ECX/RCX live-ins without truncating a pointer argument");

        const std::vector<uint8_t> subregisterBytes{2, 3, 4, 5};
        auto subregisterRead = [&](uint64_t address, void* output, size_t size) {
            if (address > subregisterBytes.size() ||
                size > subregisterBytes.size() - address)
                return false;
            std::memcpy(output, subregisterBytes.data() + address, size);
            return true;
        };
        const std::string narrowReadSource = decompile(
            mixedWidthEngine, subregisterRead, 0, 1, nullptr, nullptr,
            "x86-64");
        CHECK(narrowReadSource.find("((uint8_t)(rax))") != std::string::npos,
              "mask AL reads instead of consuming undefined upper RAX bits");
        const std::string alWriteSource = decompile(
            mixedWidthEngine, subregisterRead, 1, 2, nullptr, nullptr,
            "x86-64");
        CHECK(alWriteSource.find("rax = (rax &") != std::string::npos &&
                  alWriteSource.find("& 255ULL) << 0") != std::string::npos,
              "preserve upper RAX bits on AL writes");
        const std::string ahWriteSource = decompile(
            mixedWidthEngine, subregisterRead, 2, 3, nullptr, nullptr,
            "x86-64");
        CHECK(ahWriteSource.find("rax = (rax &") != std::string::npos &&
                  ahWriteSource.find("& 255ULL) << 8") != std::string::npos,
              "merge AH writes into bits 8 through 15");
        const std::string eaxWriteSource = decompile(
            mixedWidthEngine, subregisterRead, 3, 4, nullptr, nullptr,
            "x86-64");
        CHECK(eaxWriteSource.find("rax = (uint32_t)(4294967295);") !=
                  std::string::npos,
              "zero-extend EAX writes into RAX");
    }

    {
        SleighEngine stackEscapeEngine;
        std::string stackEscapeError;
        CHECK(stackEscapeEngine.loadSpec(stackEscapeSpec, stackEscapeError),
              "load x86 stack-address escape specification");
        const std::vector<uint8_t> stackEscapeBytes{1};
        auto stackEscapeRead = [&](uint64_t address, void* output, size_t size) {
            if (address > stackEscapeBytes.size() ||
                size > stackEscapeBytes.size() - address)
                return false;
            std::memcpy(output, stackEscapeBytes.data() + address, size);
            return true;
        };
        FunctionSignature stackEscapeSignature;
        const std::string stackEscapeSource = decompileTyped(
            stackEscapeEngine, stackEscapeRead, 0, 1, "x86-64-win64",
            "stack_escape", stackEscapeSignature, nullptr, nullptr, true);
        CHECK(stackEscapeSource.find(
                  "recovered_store<uint64_t>(rsp + 8, rcx);") !=
                  std::string::npos &&
                  stackEscapeSource.find("local_m8 = rcx") ==
                  std::string::npos,
              "keep address-escaped stack slots memory-backed in recovered projects");
    }

    {
        SleighEngine stackArgumentEngine;
        std::string stackArgumentError;
        CHECK(stackArgumentEngine.loadSpec(win64StackArgumentSpec,
                                           stackArgumentError),
              "load Win64 stack-argument specification");
        const std::vector<uint8_t> stackArgumentBytes{1, 2, 3, 1, 4, 5, 3};
        auto stackArgumentRead = [&](uint64_t address, void* output, size_t size) {
            if (address > stackArgumentBytes.size() ||
                size > stackArgumentBytes.size() - address)
                return false;
            std::memcpy(output, stackArgumentBytes.data() + address, size);
            return true;
        };
        CfgBuilder calleeCfg;
        CHECK(calleeCfg.build(stackArgumentEngine, stackArgumentRead, 0, 3),
              "build Win64 stack-argument callee");
        FunctionIR calleeIr;
        CHECK(calleeIr.build(calleeCfg, "x86-64", "win64"),
              "construct Win64 stack-argument SSA");
        const FunctionSignature calleeSignature = calleeIr.inferSignature();
        CHECK(calleeSignature.parameters.size() == 1 &&
                  calleeSignature.parameters[0].onStack &&
                  calleeSignature.parameters[0].stackOffset == 40,
              "normalize Win64 stack input to the function-entry SP");
        const std::string calleeSource = decompileTyped(
            stackArgumentEngine, stackArgumentRead, 0, 3, "x86-64",
            "callee", calleeSignature, nullptr, nullptr, true);
        CHECK(calleeSource.find(
                  "recovered_store<std::uint64_t>(rsp + 40, stack_arg0);") !=
                  std::string::npos,
              "initialize a recovered Win64 callee stack argument at entry SP+40");

        const std::function<std::string(uint64_t)> stackNameOf =
            [](uint64_t target) { return target == 0 ? "callee" : ""; };
        const std::function<std::optional<FunctionSignature>(uint64_t)>
            stackSignatureOf = [&](uint64_t target) {
                return target == 0
                           ? std::optional<FunctionSignature>(calleeSignature)
                           : std::nullopt;
            };
        FunctionSignature callerSignature;
        const std::string callerSource = decompileTyped(
            stackArgumentEngine, stackArgumentRead, 3, 7, "x86-64",
            "caller", callerSignature, stackNameOf, stackSignatureOf, true);
        CHECK(callerSource.find(
                  "callee(recovered_load<std::uint64_t>(rsp + 32))") !=
                  std::string::npos,
              "account for the x86 return address at a recovered Win64 call");

        const std::function<std::string(uint64_t)> externalNameOf =
            [](uint64_t target) { return target == 0 ? "external_call" : ""; };
        const std::string unknownCallerSource = decompileTyped(
            stackArgumentEngine, stackArgumentRead, 3, 7, "x86-64-win64",
            "unknown_caller", callerSignature, externalNameOf, nullptr, true);
        CHECK(unknownCallerSource.find(
                  "external_call(rcx, rdx, r8, r9, "
                  "recovered_load<std::uint64_t>(rsp + 32), "
                  "recovered_load<std::uint64_t>(rsp + 40), "
                  "recovered_load<std::uint64_t>(rsp + 48), "
                  "recovered_load<std::uint64_t>(rsp + 56))") !=
                  std::string::npos,
              "forward Win64 stack arguments to imports without recovered signatures");
    }

    const size_t liveBefore = ir.liveOpCount();
    ir.optimize();
    CHECK(ir.liveOpCount() < liveBefore, "optimizer removes copy/add-zero work");

    // An indirect branch through a constant table base recovers executable
    // pointer entries and stops at the first invalid target.
    std::vector<uint8_t> dispatch(64, 6);
    dispatch[0] = 5;
    MemoryImage memory;
    CHECK(memory.addBlock("code", 0, dispatch,
                          static_cast<int>(Perm::R) | static_cast<int>(Perm::X)),
          "map executable dispatch block");
    std::vector<uint8_t> table(24, 0);
    const uint64_t targets[] = {0x20, 0x30, 0x1000};
    std::memcpy(table.data(), targets, sizeof(targets));
    CHECK(memory.addBlock("table", 0x100, table, static_cast<int>(Perm::R)),
          "map jump table");
    auto memRead = [&](uint64_t address, void* out, size_t size) {
        return memory.read(address, out, size);
    };
    CfgBuilder indirectCfg;
    CHECK(indirectCfg.build(engine, memRead, 0, 1), "build indirect-branch CFG");
    const auto tables = recoverJumpTables(indirectCfg, memory);
    CHECK(tables.size() == 1, "recover one jump table");
    CHECK(!tables.empty() && tables[0].targets.size() == 2,
          "recover valid jump-table targets only");
    const HighFunction diamondHigh = HighIRBuilder().build(cfg);
    CHECK(diamondHigh.root &&
              diamondHigh.dump().find("if_else") != std::string::npos,
          "HighIR structures a canonical diamond as an if/else AST node");
    const HighFunction switchHigh = HighIRBuilder().build(indirectCfg, tables);
    CHECK(switchHigh.root &&
              switchHigh.dump().find("switch") != std::string::npos &&
              switchHigh.dump().find("case 1") != std::string::npos,
          "HighIR turns recovered jump tables into switch/case nodes");

    Program program;
    program.arch = "generic";
    std::vector<uint8_t> programBytes(16, 6);
    programBytes[0] = 7;
    programBytes[1] = 6;
    programBytes[2] = 13;
    programBytes[8] = 4;
    programBytes[12] = 9;
    CHECK(program.memory.addBlock("code", 0, programBytes,
                                  static_cast<int>(Perm::R) |
                                      static_cast<int>(Perm::X)),
          "map program-analysis code");
    program.symbols.push_back(Symbol{"caller", 0, 2, true, false});
    program.symbols.push_back(Symbol{"callee", 8, 1, true, false});
    program.symbols.push_back(Symbol{"reader_caller", 2, 2, true, false});
    program.symbols.push_back(Symbol{"reader", 12, 1, true, false});
    ProgramAnalysis wholeProgram;
    CHECK(wholeProgram.build(program, engine), "build whole-program analysis");
    const AnalyzedFunction* caller = wholeProgram.functionAt(0);
    const AnalyzedFunction* callee = wholeProgram.functionAt(8);
    CHECK(caller && caller->callees == std::vector<uint64_t>{8},
          "call graph records direct callee");
    CHECK(callee && callee->callers == std::vector<uint64_t>{0},
          "call graph records reverse caller edge");
    CHECK(callee && callee->signature.parameters.size() == 1,
          "callee data flow recovers one live ABI parameter");
    const std::string typed = wholeProgram.decompileFunction(program, engine, 0);
    CHECK(typed.find("caller(uint64_t arg0") != std::string::npos,
          "typed decompilation preserves ABI inputs forwarded by a call");
    CHECK(typed.find("callee(r1)") != std::string::npos,
          "call emission uses propagated callee arity instead of eight arguments");
    CHECK(typed.find("return;") != std::string::npos,
          "typed void function emits a valid empty return");
    const auto readerEffects = wholeProgram.effectsAt(12);
    const auto readerCallerEffects = wholeProgram.effectsAt(2);
    CHECK(readerEffects && readerEffects->modRef() == ModRefInfo::REF,
          "local Mod/Ref summary records memory reads");
    CHECK(readerCallerEffects && readerCallerEffects->modRef() == ModRefInfo::REF,
          "Mod/Ref summary propagates reads across the call graph");

    Program dynamicProgram;
    dynamicProgram.arch = "generic";
    std::vector<uint8_t> dynamicBytes(32, 6);
    dynamicBytes[0] = 7;   // symbol -> unwind-described function at 8
    dynamicBytes[8] = 20;  // unwind function -> leaf without unwind metadata
    dynamicBytes[20] = 6;
    CHECK(dynamicProgram.memory.addBlock(
              "dynamic-code", 0, dynamicBytes,
              static_cast<int>(Perm::R) | static_cast<int>(Perm::X)),
          "map dynamic-discovery program");
    dynamicProgram.symbols.push_back(Symbol{"dynamic_root", 0, 2, true, false});
    dynamicProgram.exceptionRegions.push_back(ExceptionRegion{
        ExceptionRegion::WINDOWS_UNWIND, 8, 9, 0, 0, 0});
    ProgramAnalysis dynamicAnalysis;
    CHECK(dynamicAnalysis.build(dynamicProgram, engine),
          "analyze calls originating in an unwind-described function");
    CHECK(dynamicAnalysis.functionAt(20) != nullptr,
          "whole-program analysis dynamically discovers a direct leaf without unwind metadata");

    std::vector<uint8_t> aggregateBytes(8, 6);
    aggregateBytes[0] = 9;
    auto aggregateRead = [&](uint64_t address, void* out, size_t size) {
        if (address > aggregateBytes.size() ||
            size > aggregateBytes.size() - address)
            return false;
        std::memcpy(out, aggregateBytes.data() + address, size);
        return true;
    };
    CfgBuilder aggregateCfg;
    CHECK(aggregateCfg.build(engine, aggregateRead, 0, 1),
          "build aggregate-access function");
    FunctionIR aggregateIr;
    CHECK(aggregateIr.build(aggregateCfg, "generic"),
          "analyze aggregate-access function");
    const FunctionSignature aggregateSignature = aggregateIr.inferSignature();
    const DataType* aggregateParameter = aggregateSignature.parameters.empty()
                                             ? nullptr
                                             : &aggregateSignature.parameters[0].type;
    CHECK(aggregateParameter && aggregateParameter->kind == TypeKind::POINTER &&
              aggregateParameter->detail && aggregateParameter->detail->elementType &&
              aggregateParameter->detail->elementType->kind == TypeKind::ARRAY &&
              aggregateParameter->detail->elementType->detail &&
              aggregateParameter->detail->elementType->detail->elementCount == 3,
          "equal-stride field accesses recover a three-element array type");
    const MidInstruction* aggregateSecondLoad = nullptr;
    size_t aggregateLoadIndex = 0;
    for (const MidBlock& block : aggregateIr.blocks())
        for (const MidInstruction& operation : block.ops)
            if (operation.op == POp::LOAD && aggregateLoadIndex++ == 1)
                aggregateSecondLoad = &operation;
    const MemoryLocation arrayField = aggregateSecondLoad
        ? AliasAnalysis(aggregateIr).location(aggregateSecondLoad->inputs[0], 8)
        : MemoryLocation{};
    CHECK(arrayField.fieldPath == "[1]",
          "field-sensitive alias analysis records recovered array indices");

    std::vector<uint8_t> indirectCallBytes(8, 6);
    indirectCallBytes[0] = 10;
    auto indirectCallRead = [&](uint64_t address, void* out, size_t size) {
        if (address > indirectCallBytes.size() ||
            size > indirectCallBytes.size() - address)
            return false;
        std::memcpy(out, indirectCallBytes.data() + address, size);
        return true;
    };
    CfgBuilder indirectCallCfg;
    CHECK(indirectCallCfg.build(engine, indirectCallRead, 0, 1),
          "build indirect-call function");
    FunctionIR indirectCallIr;
    CHECK(indirectCallIr.build(indirectCallCfg, "generic"),
          "analyze indirect-call function");
    const FunctionSignature indirectCallSignature = indirectCallIr.inferSignature();
    CHECK(!indirectCallSignature.parameters.empty() &&
              indirectCallSignature.parameters[0].type.kind ==
                  TypeKind::FUNCTION_POINTER,
          "indirect call target propagates a function-pointer type to its ABI input");
    CHECK(indirectCallSignature.parameters.size() == 4,
          "indirect call forwards every untouched ABI argument register");

    std::vector<uint8_t> tailBytes(80, 6);
    tailBytes[0] = 21;
    auto tailRead = [&](uint64_t address, void* out, size_t size) {
        if (address > tailBytes.size() || size > tailBytes.size() - address)
            return false;
        std::memcpy(out, tailBytes.data() + address, size);
        return true;
    };
    CfgBuilder tailCfg;
    CHECK(tailCfg.build(engine, tailRead, 0, 1),
          "build bounded ABI-forwarding tail call");
    CHECK(!tailCfg.blocks().empty() && tailCfg.blocks()[0].isTailCall(),
          "bounded external branch is represented as a tail call");
    FunctionIR tailIr;
    CHECK(tailIr.build(tailCfg, "generic"),
          "analyze ABI-forwarding tail call");
    CHECK(tailIr.inferSignature().parameters.size() == 4,
          "tail call forwards every untouched ABI argument register");
    CHECK(tailIr.inferSignature().returnType.kind != TypeKind::VOID_TYPE,
          "tail call preserves its target's machine return value");

    auto buildSingle = [&](uint8_t opcode, FunctionIR& result) {
        std::vector<uint8_t> image(8, 6);
        image[0] = opcode;
        auto imageRead = [&](uint64_t address, void* out, size_t size) {
            if (address > image.size() || size > image.size() - address)
                return false;
            std::memcpy(out, image.data() + address, size);
            return true;
        };
        CfgBuilder singleCfg;
        return singleCfg.build(engine, imageRead, 0, 1) &&
               result.build(singleCfg, "generic");
    };
    auto liveLoads = [](const FunctionIR& function) {
        size_t count = 0;
        for (const MidBlock& block : function.blocks())
            for (const MidInstruction& operation : block.ops)
                count += !operation.removed && operation.op == POp::LOAD;
        return count;
    };

    FunctionIR noAliasIr;
    CHECK(buildSingle(11, noAliasIr), "lower no-alias memory function to MidIR");
    CHECK(noAliasIr.verify().valid(), "MidIR verifier accepts lowered memory SSA");
    const MidInstruction* firstLoad = nullptr;
    const MidInstruction* secondLoad = nullptr;
    const MidInstruction* store = nullptr;
    for (const MidBlock& block : noAliasIr.blocks())
        for (const MidInstruction& operation : block.ops) {
            if (operation.op == POp::LOAD) {
                if (!firstLoad) firstLoad = &operation;
                else secondLoad = &operation;
            }
            if (operation.op == POp::STORE) store = &operation;
        }
    CHECK(firstLoad && classifyMidOperation(*firstLoad) ==
                           MidOperationClass::MEMORY_READ &&
              store && classifyMidOperation(*store) ==
                           MidOperationClass::MEMORY_WRITE,
          "MidIR classifies memory operations independently of source p-code");
    CHECK(noAliasIr.memoryPartitions().size() >= 3 && firstLoad && secondLoad &&
              store && firstLoad->memoryPartition == secondLoad->memoryPartition &&
              firstLoad->memoryPartition != store->memoryPartition &&
              firstLoad->memoryVersionIn == secondLoad->memoryVersionIn,
          "MemorySSA partitions independent fields and preserves unaffected versions");
    AliasAnalysis noAliasAnalysis(noAliasIr);
    CHECK(firstLoad && store &&
              noAliasAnalysis.alias(firstLoad->inputs[0], 8,
                                    store->inputs[0], 8) ==
                  AliasResult::NO_ALIAS,
          "alias analysis proves disjoint constant-offset fields do not alias");
    CHECK(firstLoad &&
              noAliasAnalysis.alias(firstLoad->inputs[0], 8,
                                    firstLoad->inputs[0], 8) ==
                  AliasResult::MUST_ALIAS,
          "alias analysis identifies identical memory locations");
    CHECK(firstLoad && store &&
              noAliasAnalysis.alias(firstLoad->inputs[0], 24,
                                    store->inputs[0], 8) ==
                  AliasResult::PARTIAL_ALIAS,
          "alias analysis detects partially overlapping byte ranges");
    CHECK(liveLoads(noAliasIr) == 2,
          "two loads exist before alias-aware optimization");
    noAliasIr.optimize();
    CHECK(liveLoads(noAliasIr) == 1,
          "load forwarding crosses a proven non-aliasing store");

    FunctionIR mayAliasIr;
    CHECK(buildSingle(12, mayAliasIr), "lower may-alias memory function to MidIR");
    mayAliasIr.optimize();
    CHECK(liveLoads(mayAliasIr) == 2,
          "unknown parameter aliasing conservatively blocks load forwarding");

    FunctionIR heapGlobalIr;
    CHECK(buildSingle(14, heapGlobalIr), "lower heap/global alias function");
    const MidInstruction* heapLoad = nullptr;
    const MidInstruction* globalLoad = nullptr;
    for (const MidBlock& block : heapGlobalIr.blocks())
        for (const MidInstruction& operation : block.ops)
            if (operation.op == POp::LOAD) {
                if (!heapLoad) heapLoad = &operation;
                else globalLoad = &operation;
            }
    if (heapLoad) {
        MemoryObject heap;
        heap.kind = MemoryObjectKind::HEAP;
        heap.value = heapLoad->inputs[0];
        heap.allocationSite = 0xfeed;
        heap.name = "malloc@0xfeed";
        heapGlobalIr.addMemoryObject(std::move(heap));
    }
    const AliasAnalysis heapAliases(heapGlobalIr);
    CHECK(heapLoad && globalLoad &&
              heapAliases.alias(heapLoad->inputs[0], 8,
                                globalLoad->inputs[0], 8) ==
                  AliasResult::NO_ALIAS,
          "heap allocation objects are disjoint from absolute global objects");

    Program cppProgram;
    cppProgram.format = "ELF64";
    cppProgram.arch = "x86-64";
    std::vector<uint8_t> cppCode(0x40, 0x90);
    CHECK(cppProgram.memory.addBlock(".text", 0x20, cppCode,
                                     static_cast<int>(Perm::R) |
                                         static_cast<int>(Perm::X)),
          "map synthetic C++ virtual functions");
    std::vector<uint8_t> cppData(0xc0, 0);
    auto putPointer = [&](uint64_t address, uint64_t value) {
        std::memcpy(cppData.data() + (address - 0x100), &value, sizeof(value));
    };
    putPointer(0x108, 0x180); putPointer(0x110, 0x20);
    putPointer(0x128, 0x1a0); putPointer(0x130, 0x30);
    putPointer(0x138, static_cast<uint64_t>(-16));
    putPointer(0x140, 0x1a0); putPointer(0x148, 0x20);
    putPointer(0x1a0 + 16, 0x180);
    CHECK(cppProgram.memory.addBlock(".rodata", 0x100, cppData,
                                     static_cast<int>(Perm::R)),
          "map synthetic Itanium RTTI and vtables");
    cppProgram.symbols.push_back(Symbol{"_ZTV4Base", 0x100, 24, false, false});
    cppProgram.symbols.push_back(Symbol{"_ZTI4Base", 0x180, 24, false, false});
    cppProgram.symbols.push_back(Symbol{"_ZTV7Derived", 0x120, 24, false, false});
    cppProgram.symbols.push_back(Symbol{"_ZTI7Derived", 0x1a0, 24, false, false});
    cppProgram.symbols.push_back(Symbol{"_ZTI3BoxIiE", 0x1b8, 8, false, false});
    cppProgram.symbols.push_back(Symbol{"Base::run", 0x20, 1, true, false});
    cppProgram.symbols.push_back(Symbol{"Derived::run", 0x30, 1, true, false});
    const CppRecoveryResult cppTypes = recoverCppTypes(cppProgram);
    const auto derived = std::find_if(
        cppTypes.classes.begin(), cppTypes.classes.end(),
        [](const CppClassInfo& info) { return info.name == "Derived"; });
    CHECK(derived != cppTypes.classes.end() &&
              derived->virtualFunctions.size() == 1 &&
              derived->virtualFunctions[0].name == "Derived::run" &&
              derived->bases.size() == 1 && derived->bases[0].name == "Base" &&
              derived->vtableGroups.size() == 2 &&
              derived->vtableGroups[1].offsetToTop == -16,
          "recover Itanium class inheritance and virtual function slots");
    const auto box = std::find_if(
        cppTypes.classes.begin(), cppTypes.classes.end(),
        [](const CppClassInfo& info) { return info.name == "Box<int>"; });
    CHECK(box != cppTypes.classes.end() &&
              box->templateInfo.isInstantiation &&
              box->templateInfo.primaryName == "Box" &&
              box->templateInfo.arguments == std::vector<std::string>{"int"},
          "recover structured Itanium template instantiation arguments");
    CppRecoveryResult secondModule;
    CppClassInfo externalBase;
    externalBase.name = "Derived";
    externalBase.abi = CppAbi::ITANIUM;
    externalBase.bases.push_back({"ExternalBase", 0x500, 16, false});
    secondModule.classes.push_back(std::move(externalBase));
    const CppRecoveryResult mergedCpp =
        mergeCppRecoveryResults({cppTypes, secondModule});
    const auto mergedDerived = std::find_if(
        mergedCpp.classes.begin(), mergedCpp.classes.end(),
        [](const CppClassInfo& info) { return info.name == "Derived"; });
    CHECK(mergedDerived != mergedCpp.classes.end() &&
              mergedDerived->bases.size() == 2,
          "propagate recovered C++ inheritance across module boundaries");

    Program objectProgram;
    objectProgram.format = "PE64";
    objectProgram.arch = "x86-64";
    std::vector<uint8_t> objectCode(16, 6);
    objectCode[0] = 15;
    objectCode[1] = 16;
    objectCode[2] = 17;
    objectCode[6] = 18;
    objectCode[8] = 19;
    CHECK(objectProgram.memory.addBlock(".text", 0x20, objectCode,
                                        static_cast<int>(Perm::R) |
                                            static_cast<int>(Perm::X)),
          "map synthetic C++ object methods");
    std::vector<uint8_t> objectVtable(0x30, 0);
    const uint64_t virtualTarget = 0x23;
    std::memcpy(objectVtable.data(), &virtualTarget, sizeof(virtualTarget));
    const uint64_t memberFunctionOffset = 1;
    const uint64_t memberThisAdjustment = 8;
    std::memcpy(objectVtable.data() + 0x10, &memberFunctionOffset,
                sizeof(memberFunctionOffset));
    std::memcpy(objectVtable.data() + 0x18, &memberThisAdjustment,
                sizeof(memberThisAdjustment));
    CHECK(objectProgram.memory.addBlock(".rdata", 0x100, objectVtable,
                                        static_cast<int>(Perm::R)),
          "map synthetic MSVC object vtable");
    objectProgram.symbols.push_back(
        Symbol{"??_7Widget@@6B@", 0x100, 8, false, false});
    objectProgram.symbols.push_back(
        Symbol{"Widget::Widget", 0x20, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"Widget::invoke", 0x21, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"Widget::dispatch", 0x22, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"Widget::run", 0x23, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"object_helper", 0x24, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"__dynamic_cast", 0x25, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"Widget::cast", 0x26, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"_ZnwmPv", 0x27, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"makeWidget", 0x28, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"_ZThn16_N6Widget3runEv", 0x29, 1, true, false});
    objectProgram.symbols.push_back(
        Symbol{"Widget::instanceCount", 0x108, 8, false, false});
    objectProgram.symbols.push_back(
        Symbol{"Widget::run_member_ptr", 0x110, 16, false, false});
    objectProgram.symbols.push_back(
        Symbol{"??_8Widget@@7B@", 0x120, 8, false, false});
    ExceptionRegion objectException;
    objectException.kind = ExceptionRegion::WINDOWS_UNWIND;
    objectException.start = 0x21;
    objectException.end = 0x22;
    objectException.handlers.push_back({0x21, 0x22, 0x23, 2});
    objectProgram.exceptionRegions.push_back(std::move(objectException));
    ProgramAnalysis objectAnalysis;
    CHECK(objectAnalysis.build(objectProgram, engine),
          "build C++ object recovery graph");
    const CppRecoveryResult& objectTypes = objectAnalysis.cppTypes();
    const auto widget = std::find_if(
        objectTypes.classes.begin(), objectTypes.classes.end(),
        [](const CppClassInfo& info) { return info.name == "Widget"; });
    CHECK(widget != objectTypes.classes.end() &&
              widget->fields.size() == 2 && widget->fields[0].isVptr &&
              widget->fields[0].byteOffset == 0 &&
              widget->fields[1].byteOffset == 8 &&
              widget->inferredSize == 16 &&
              widget->inferredAlignment == 8,
          "recover vptr, member field, class size, and alignment");
    CHECK(widget != objectTypes.classes.end() &&
              std::find(widget->staticMembers.begin(),
                        widget->staticMembers.end(),
                        "Widget::instanceCount") != widget->staticMembers.end(),
          "associate class-owned static storage");
    const auto constructor = std::find_if(
        objectTypes.objectGraph.methods.begin(),
        objectTypes.objectGraph.methods.end(),
        [](const CppMethodInfo& method) { return method.address == 0x20; });
    CHECK(constructor != objectTypes.objectGraph.methods.end() &&
              constructor->role == CppMethodRole::CONSTRUCTOR &&
              constructor->hasThis && constructor->confidence >= 0.98,
          "recognize constructor from symbol and vptr initialization");
    CHECK(objectTypes.objectGraph.vptrWrites.size() == 1 &&
              objectTypes.objectGraph.vptrWrites[0].className == "Widget" &&
              objectTypes.objectGraph.vptrWrites[0].objectOffset == 0,
          "record evidence-backed vptr initialization");
    CHECK(objectTypes.objectGraph.virtualCalls.size() == 1 &&
              objectTypes.objectGraph.virtualCalls[0].className == "Widget" &&
              objectTypes.objectGraph.virtualCalls[0].slot == 0 &&
              objectTypes.objectGraph.virtualCalls[0].resolvedTarget == 0x23,
          "recover and resolve a typed virtual-call site");
    const auto helperClass =
        objectTypes.objectGraph.functionClasses.find(0x24);
    CHECK(helperClass != objectTypes.objectGraph.functionClasses.end() &&
              helperClass->second == "Widget",
          "propagate class identity through a uniquely owned helper call");
    const bool hasConstructedObject = std::any_of(
        objectTypes.objectGraph.objects.begin(),
        objectTypes.objectGraph.objects.end(),
        [](const CppObjectCandidate& object) {
            return object.className == "Widget" && !object.lifetime.empty() &&
                   object.lifetime[0].kind ==
                       CppLifetimeEventKind::CONSTRUCT;
        });
    CHECK(hasConstructedObject,
          "create an object lifetime candidate for the constructor");
    const auto virtualMethod = std::find_if(
        objectTypes.objectGraph.methods.begin(),
        objectTypes.objectGraph.methods.end(),
        [](const CppMethodInfo& method) { return method.address == 0x23; });
    const auto adjustorThunk = std::find_if(
        objectTypes.objectGraph.methods.begin(),
        objectTypes.objectGraph.methods.end(),
        [](const CppMethodInfo& method) { return method.address == 0x29; });
    CHECK(virtualMethod != objectTypes.objectGraph.methods.end() &&
              virtualMethod->role == CppMethodRole::VIRTUAL_METHOD &&
              virtualMethod->virtualSlot == 0 &&
              adjustorThunk != objectTypes.objectGraph.methods.end() &&
              adjustorThunk->role == CppMethodRole::ADJUSTOR_THUNK &&
              adjustorThunk->thisAdjustment == -16,
          "recover virtual method roles and adjustor-thunk this offsets");
    CHECK(widget != objectTypes.classes.end() &&
              widget->hasVirtualInheritance &&
              objectTypes.objectGraph.memberPointers.size() == 1 &&
              objectTypes.objectGraph.memberPointers[0].ownerClass == "Widget" &&
              objectTypes.objectGraph.memberPointers[0].isVirtual &&
              objectTypes.objectGraph.memberPointers[0].thisAdjustment == 8,
          "recover vbtable evidence and member-function pointer layout");
    const bool hasDynamicCast = std::any_of(
        objectTypes.objectGraph.runtimeOperations.begin(),
        objectTypes.objectGraph.runtimeOperations.end(),
        [](const CppRuntimeOperation& operation) {
            return operation.kind == CppRuntimeOperationKind::DYNAMIC_CAST &&
                   operation.className == "Widget";
        });
    const bool hasCatch = std::any_of(
        objectTypes.objectGraph.runtimeOperations.begin(),
        objectTypes.objectGraph.runtimeOperations.end(),
        [](const CppRuntimeOperation& operation) {
            return operation.kind == CppRuntimeOperationKind::BEGIN_CATCH &&
                   operation.landingPad == 0x23 && operation.action == 2;
        });
    const bool hasPlacementObject = std::any_of(
        objectTypes.objectGraph.objects.begin(),
        objectTypes.objectGraph.objects.end(),
        [](const CppObjectCandidate& object) {
            return object.className == "Widget" && object.placementNew;
        });
    CHECK(hasDynamicCast && hasCatch && hasPlacementObject,
          "recognize dynamic_cast, exception actions, and placement new");
    const CppRecoveryResult twiceMerged =
        mergeCppRecoveryResults({objectTypes, objectTypes});
    std::vector<uint64_t> mergedObjectIds;
    for (const CppObjectCandidate& object : twiceMerged.objectGraph.objects)
        mergedObjectIds.push_back(object.id);
    std::sort(mergedObjectIds.begin(), mergedObjectIds.end());
    CHECK(std::adjacent_find(mergedObjectIds.begin(), mergedObjectIds.end()) ==
              mergedObjectIds.end(),
          "rebase object identities while merging recovery graphs");
    const ProgramKnowledgeGraph knowledge =
        buildProgramKnowledgeGraph(objectProgram, objectAnalysis);
    const auto widgetNode = knowledge.find("class:Widget");
    CHECK(widgetNode && knowledge.nodes().size() >= 20 &&
              std::any_of(knowledge.edges().begin(), knowledge.edges().end(),
                  [](const KnowledgeEdge& edge) {
                      return edge.kind == KnowledgeEdgeKind::RESOLVES_TO;
                  }) &&
              knowledge.toJson().find("\"kind\":\"class\"") !=
                  std::string::npos,
          "unify functions, classes, objects, and virtual calls in a knowledge graph");

    Program unwindProgram;
    unwindProgram.arch = "generic";
    std::vector<uint8_t> unwindCode(4, 6);
    CHECK(unwindProgram.memory.addBlock("code", 0, unwindCode,
                                        static_cast<int>(Perm::R) |
                                            static_cast<int>(Perm::X)),
          "map unwind-only function fixture");
    ExceptionRegion unwindFunction;
    unwindFunction.kind = ExceptionRegion::DWARF_CFI;
    unwindFunction.start = 2;
    unwindFunction.end = 3;
    unwindProgram.exceptionRegions.push_back(std::move(unwindFunction));
    const std::vector<Function> unwindFunctions =
        findFunctions(unwindProgram, nullptr);
    CHECK(unwindFunctions.size() == 1 && unwindFunctions[0].addr == 2 &&
              unwindFunctions[0].size == 1 &&
              unwindFunctions[0].src == Function::UNWIND,
          "use FDE/RUNTIME_FUNCTION ranges as authoritative function bounds");

    Program chainedUnwindProgram;
    chainedUnwindProgram.arch = "x86-64";
    CHECK(chainedUnwindProgram.memory.addBlock(
              "code", 0x100, std::vector<uint8_t>(4, 0x90),
              static_cast<int>(Perm::R) | static_cast<int>(Perm::X)),
          "map chained Windows unwind fixture");
    ExceptionRegion chainedRoot;
    chainedRoot.start = 0x100; chainedRoot.end = 0x101;
    ExceptionRegion chainedMiddle;
    chainedMiddle.start = 0x101; chainedMiddle.end = 0x102;
    chainedMiddle.chainedStart = 0x100;
    ExceptionRegion chainedTail;
    chainedTail.start = 0x102; chainedTail.end = 0x103;
    chainedTail.chainedStart = 0x101;
    ExceptionRegion unrelated;
    unrelated.start = 0x103; unrelated.end = 0x104;
    chainedUnwindProgram.exceptionRegions = {
        chainedRoot, chainedMiddle, chainedTail, unrelated};
    const std::vector<Function> chainedFunctions =
        findFunctions(chainedUnwindProgram, nullptr);
    CHECK(chainedFunctions.size() == 2 &&
              chainedFunctions[0].addr == 0x100 &&
              chainedFunctions[0].size == 3 &&
              chainedFunctions[1].addr == 0x103 &&
              chainedFunctions[1].size == 1,
          "coalesce UNW_FLAG_CHAININFO ranges into one logical function");
    ProgramAnalysis limitedObjectAnalysis;
    CHECK(limitedObjectAnalysis.build(objectProgram, engine, "", 2) &&
              limitedObjectAnalysis.functions().size() == 2,
          "bound whole-program analysis for deterministic scale benchmarks");

    if (failures) return 1;
    std::puts("all function IR tests passed");
    return 0;
}
