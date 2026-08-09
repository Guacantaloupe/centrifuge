// ghra - a Ghidra reimplementation in C++17
// analysis.cpp - function discovery
#include "ghra/analysis.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

namespace ghra {

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
            if (src == Function::SYMBOL || src == Function::EXPORT) {
                if (it->second.src == Function::SCAN ||
                    it->second.src == Function::ENTRY) {
                    it->second.name = std::move(name);
                    it->second.src = src;
                }
            }
            if (symSize > it->second.size) it->second.size = symSize;
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

    // Seed 2: recursive-descent scan from every known start. Follows direct
    // calls (promoting targets to functions) and unconditional jumps; stops at
    // RET, unknown/indirect branches, unreadable memory, or a known function
    // start (prevents merging).
    if (disasm) {
        std::vector<uint64_t> worklist;
        for (const auto& kv : funcs) worklist.push_back(kv.first);
        std::set<uint64_t> visited;
        for (size_t wi = 0; wi < worklist.size(); ++wi) {
            uint64_t cur = worklist[wi];
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
                        addFunc(insn.target, funName(insn.target, is64),
                                Function::SCAN);
                        worklist.push_back(insn.target);
                    }
                    cur += insn.size; // keep scanning after the call
                } else if (insn.kind == Insn::JMP) {
                    if (insn.targetKnown &&
                        prog.memory.isExecutable(insn.target)) {
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

} // namespace ghra
