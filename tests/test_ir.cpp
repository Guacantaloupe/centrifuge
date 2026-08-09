// Function-level SSA, type, ABI, optimizer, and jump-table tests.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "centrifuge/ir.hpp"
#include "centrifuge/sleigh.hpp"

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

    if (failures) return 1;
    std::puts("all function IR tests passed");
    return 0;
}
