// centrifuge - a Ghidra reimplementation in C++17
// cfg.hpp - control-flow graph construction from p-code (decompiler front end)
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "centrifuge/pcode.hpp"
#include "centrifuge/sleigh.hpp"
#include "centrifuge/loader.hpp"

namespace centrifuge {

struct CfgBlock {
    uint64_t start = 0;
    uint64_t end = 0; // exclusive
    std::vector<PcodeInsn> insns;
    std::vector<uint64_t> succs; // block start addresses
    std::vector<uint64_t> calls; // direct call targets observed in this block
    std::vector<uint64_t> exceptionSuccs; // landing pads / language handlers
    std::optional<uint64_t> tailCallTarget;

    bool isRet() const {
        return !insns.empty() &&
               insns.back().kind == Insn::RET;
    }
    bool isBranch() const {
        return !insns.empty() && insns.back().kind == Insn::JMP;
    }
    bool isCondBranch() const {
        return !insns.empty() && insns.back().kind == Insn::JCC;
    }
    bool isTailCall() const { return tailCallTarget.has_value(); }
    const PcodeInsn* terminator() const {
        return insns.empty() ? nullptr : &insns.back();
    }
};

struct NaturalLoop {
    uint64_t header = 0;
    std::set<uint64_t> blocks;
    std::vector<std::pair<uint64_t, uint64_t>> backEdges; // tail -> header
    std::vector<std::pair<uint64_t, uint64_t>> exits;     // inside -> outside
    std::optional<uint64_t> parentHeader;
};

class CfgBuilder {
public:
    // Disassembles from `start` until RET / undecodable / `end` (exclusive).
    bool build(const SleighEngine& eng,
               const std::function<bool(uint64_t, void*, size_t)>& read,
               uint64_t start, uint64_t end,
               const std::function<bool(uint64_t)>& isExecutable = {});

    const std::vector<CfgBlock>& blocks() const { return blocks_; }
    const CfgBlock* blockAt(uint64_t startAddr) const;

    // Full dominator set of a block, rooted at the entry passed to build().
    std::set<uint64_t> dominators(uint64_t blockStart) const;
    std::set<uint64_t> predecessors(uint64_t blockStart) const;

    const std::vector<NaturalLoop>& loops() const { return loops_; }
    const NaturalLoop* loopByHeader(uint64_t header) const;
    const NaturalLoop* innermostLoopForBlock(uint64_t blockStart) const;

    // Add exceptional successors for instructions covered by loader-provided
    // unwind regions. These edges are kept separate from normal flow.
    void applyExceptionRegions(const std::vector<ExceptionRegion>& regions);

    std::string dot() const;

private:
    std::vector<CfgBlock> blocks_;
    std::map<uint64_t, size_t> idx_;
    uint64_t entry_ = 0;
    std::vector<NaturalLoop> loops_;
    size_t indexOf(uint64_t start) const;
    void findNaturalLoops();
};

} // namespace centrifuge
