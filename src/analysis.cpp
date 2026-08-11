// centrifuge - a Ghidra reimplementation in C++17
// analysis.cpp - function discovery
#include "centrifuge/analysis.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

namespace centrifuge {

namespace {

std::string funName(uint64_t addr, bool is64) {
    char buf[32];
    if (is64)
        std::snprintf(buf, sizeof(buf), "FUN_%016llX",
                      static_cast<unsigned long long>(addr));
    else
        std::snprintf(buf, sizeof(buf), "FUN_%08llX",
                      static_cast<unsigned long long>(addr));
    return buf;
}

} // namespace

std::vector<Function> findFunctions(const Program& prog, Disassembler* disasm) {
    const bool is64 = prog.arch != "x86" && prog.arch != "arm" &&
                      prog.arch != "mips" && prog.arch != "riscv32";

    std::map<uint64_t, Function> funcs;
    auto addFunc = [&](uint64_t addr, std::string name, Function::Src src,
                       uint64_t symSize = 0) {
        if (!prog.memory.isExecutable(addr)) return;
        auto it = funcs.find(addr);
        if (it == funcs.end()) {
            Function f;
            f.name = std::move(name);
            f.addr = addr;
            f.size = symSize;
            f.src = src;
            funcs.emplace(addr, std::move(f));
        } else {
            const bool replacesHeuristic = it->second.src == Function::SCAN ||
                                           it->second.src == Function::ENTRY;
            if (src == Function::SYMBOL || src == Function::EXPORT ||
                src == Function::UNWIND) {
                if (replacesHeuristic) {
                    it->second.name = std::move(name);
                    it->second.src = src;
                }
            }
            if (src == Function::UNWIND && replacesHeuristic)
                it->second.size = symSize;
            else if (symSize > it->second.size)
                it->second.size = symSize;
        }
    };

    // Seed 1: symbol table / exports / entry point
    for (const auto& s : prog.symbols) {
        if (!s.isFunction) continue;
        addFunc(s.addr, s.name,
                s.isExported ? Function::EXPORT : Function::SYMBOL, s.size);
    }

    if (prog.entryPoint != 0)
        addFunc(prog.entryPoint, "entry", Function::ENTRY);

    // Index authoritative unwind ranges before recursive discovery.  They are
    // deliberately not all inserted into `funcs` yet: doing so would put every
    // PE RUNTIME_FUNCTION on the discovery worklist.  The index still lets a
    // caller recognize a known function boundary without recursively decoding
    // enormous CRT/global initializers merely to rediscover their extent.
    std::map<uint64_t, const ExceptionRegion*> unwindByStart;
    for (const ExceptionRegion& region : prog.exceptionRegions)
        if (region.end > region.start)
            unwindByStart.emplace(region.start, &region);

    auto unwindRoot = [&](const ExceptionRegion& initial) {
        const ExceptionRegion* region = &initial;
        std::set<uint64_t> visited;
        while (region->chainedStart && visited.insert(region->start).second) {
            const auto parent = unwindByStart.find(region->chainedStart);
            if (parent == unwindByStart.end()) break;
            region = parent->second;
        }
        return region->start;
    };

    // A single MSVC function can have several adjacent RUNTIME_FUNCTION
    // records linked with UNW_FLAG_CHAININFO.  Treat their common root and
    // maximum end as one logical function; otherwise stack parameters used in
    // later fragments disappear from the recovered signature.
    std::map<uint64_t, uint64_t> unwindSizes;
    for (const ExceptionRegion& region : prog.exceptionRegions) {
        if (region.end <= region.start) continue;
        const uint64_t root = unwindRoot(region);
        if (region.end <= root) continue;
        const uint64_t size = region.end - root;
        auto inserted = unwindSizes.emplace(root, size);
        if (!inserted.second && size > inserted.first->second)
            inserted.first->second = size;
    }

    // Seed 2: recursive-descent scan from every known start. Follows direct
    // calls (promoting targets to functions) and unconditional jumps; stops at
    // RET, unknown/indirect branches, unreadable memory, or a known function
    // start (prevents merging).
    if (disasm) {
        std::vector<uint64_t> worklist;
        for (const auto& kv : funcs) worklist.push_back(kv.first);
        std::set<uint64_t> visited;
        for (size_t wi = 0; wi < worklist.size(); ++wi) {
            const uint64_t functionStart = worklist[wi];
            uint64_t cur = functionStart;
            bool first = true;
            while (true) {
                if (!first && funcs.count(cur)) break; // hit another function
                if (visited.count(cur)) break;
                if (!prog.memory.isExecutable(cur)) break;
                first = false;

                Insn insn;
                if (!disasm->disasmOne(prog.memory, cur, insn)) break;
                visited.insert(cur);

                if (insn.kind == Insn::RET) break;
                if (insn.kind == Insn::CALL) {
                    if (insn.targetKnown &&
                        prog.memory.isExecutable(insn.target) &&
                        !funcs.count(insn.target)) {
                        const auto unwind = unwindSizes.find(insn.target);
                        if (unwind != unwindSizes.end()) {
                            addFunc(insn.target, funName(insn.target, is64),
                                    Function::UNWIND, unwind->second);
                        } else {
                            addFunc(insn.target, funName(insn.target, is64),
                                    Function::SCAN);
                            worklist.push_back(insn.target);
                        }
                    }
                    cur += insn.size; // keep scanning after the call
                } else if (insn.kind == Insn::JMP) {
                    if (insn.targetKnown &&
                        prog.memory.isExecutable(insn.target)) {
                        const auto unwind = unwindSizes.find(insn.target);
                        if (insn.target != functionStart &&
                            unwind != unwindSizes.end()) {
                            addFunc(insn.target, funName(insn.target, is64),
                                    Function::UNWIND, unwind->second);
                            break; // tail call into an authoritative range
                        }
                        cur = insn.target;
                    } else {
                        break; // indirect/unknown jump ends linear flow
                    }
                } else {
                    cur += insn.size;
                }
            }
        }
    }

    // Seed 3: compiler-produced unwind tables provide authoritative function
    // starts and end boundaries, especially for stripped Windows x64 images.
    // Add these after recursive descent so hundreds of thousands of .pdata
    // entries do not each trigger a redundant discovery walk.
    for (const auto& unwind : unwindSizes)
        addFunc(unwind.first, funName(unwind.first, is64), Function::UNWIND,
                unwind.second);

    // Sizes: distance to next function start, clamped to the containing block.
    std::vector<Function> out;
    out.reserve(funcs.size());
    for (const auto& kv : funcs) out.push_back(kv.second);
    std::sort(out.begin(), out.end(),
              [](const Function& a, const Function& b) { return a.addr < b.addr; });
    for (size_t i = 0; i < out.size(); ++i) {
        const uint64_t end =
            (i + 1 < out.size()) ? out[i + 1].addr : UINT64_MAX;
        const MemoryBlock* blk = prog.memory.blockAt(out[i].addr);
        if (!blk) continue;
        const uint64_t blkEnd = blk->end();
        const uint64_t limit = std::min(end, blkEnd);
        if (limit > out[i].addr) {
            const uint64_t byGap = limit - out[i].addr;
            if (out[i].size == 0 || byGap < out[i].size) out[i].size = byGap;
        }
    }
    return out;
}

} // namespace centrifuge
