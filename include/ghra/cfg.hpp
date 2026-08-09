// ghra - a Ghidra reimplementation in C++17
// cfg.hpp - control-flow graph construction from p-code (decompiler front end)
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ghra/pcode.hpp"
#include "ghra/sleigh.hpp"

namespace ghra {

struct CfgBlock {
    uint64_t start = 0;
    uint64_t end = 0; // exclusive
    std::vector<PcodeInsn> insns;
    std::vector<uint64_t> succs; // block start addresses

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
    const PcodeInsn* terminator() const {
        return insns.empty() ? nullptr : &insns.back();
    }
};

class CfgBuilder {
public:
    // Disassembles from `start` until RET / undecodable / `end` (exclusive).
    bool build(const SleighEngine& eng,
               const std::function<bool(uint64_t, void*, size_t)>& read,
               uint64_t start, uint64_t end);

    const std::vector<CfgBlock>& blocks() const { return blocks_; }
    const CfgBlock* blockAt(uint64_t startAddr) const;

    // immediate dominator set of a block (iterative dataflow)
    std::set<uint64_t> dominators(uint64_t blockStart) const;
    std::set<uint64_t> predecessors(uint64_t blockStart) const;

    std::string dot() const;

private:
    std::vector<CfgBlock> blocks_;
    std::map<uint64_t, size_t> idx_;
    size_t indexOf(uint64_t start) const;
};

} // namespace ghra
