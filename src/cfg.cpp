// centrifuge - a Ghidra reimplementation in C++17
// cfg.cpp - control-flow graph construction + dominators
#include "centrifuge/cfg.hpp"

#include <algorithm>
#include <cstdio>
#include <set>

namespace centrifuge {

bool CfgBuilder::build(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end) {
    blocks_.clear();
    idx_.clear();
    std::vector<uint64_t> worklist{start};
    std::set<uint64_t> starts{start}; // known block starts (boundaries)
    std::set<uint64_t> built;
    while (!worklist.empty()) {
        const uint64_t a = worklist.back();
        worklist.pop_back();
        if (built.count(a)) continue;
        built.insert(a);

        CfgBlock blk;
        blk.start = a;
        uint64_t cur = a;
        for (;;) {
            if (end != 0 && cur >= end) {
                blk.end = cur;
                break;
            }
            // stop at the start of another block (fallthrough edge)
            if (cur != a && starts.count(cur)) {
                blk.end = cur;
                blk.succs.push_back(cur);
                break;
            }
            PcodeInsn pi;
            std::string err;
            if (!eng.disassemble(read, cur, pi, err)) {
                blk.end = cur;
                break;
            }
            blk.insns.push_back(pi);
            cur += pi.size;
            if (pi.kind == Insn::RET) {
                blk.end = cur;
                break;
            }
            if (pi.kind == Insn::JMP) {
                blk.end = cur;
                if (pi.targetKnown && starts.insert(pi.target).second)
                    worklist.push_back(pi.target);
                break;
            }
            if (pi.kind == Insn::JCC) {
                blk.end = cur;
                blk.succs.push_back(cur); // fallthrough first
                if (starts.insert(cur).second) worklist.push_back(cur);
                if (pi.targetKnown) {
                    blk.succs.push_back(pi.target);
                    if (starts.insert(pi.target).second)
                        worklist.push_back(pi.target);
                }
                break;
            }
            // CALL / OTHER: block continues
        }
        blocks_.push_back(blk);
        idx_[a] = blocks_.size() - 1;
    }
    return !blocks_.empty();
}

const CfgBlock* CfgBuilder::blockAt(uint64_t startAddr) const {
    auto it = idx_.find(startAddr);
    return it == idx_.end() ? nullptr : &blocks_[it->second];
}

size_t CfgBuilder::indexOf(uint64_t start) const {
    auto it = idx_.find(start);
    return it == idx_.end() ? SIZE_MAX : it->second;
}

std::set<uint64_t> CfgBuilder::predecessors(uint64_t blockStart) const {
    std::set<uint64_t> p;
    for (const auto& b : blocks_)
        for (uint64_t s : b.succs)
            if (s == blockStart) p.insert(b.start);
    return p;
}

std::set<uint64_t> CfgBuilder::dominators(uint64_t blockStart) const {
    // iterative dataflow: dom(b) = {b} ∪ ⋂ dom(p)
    std::set<uint64_t> all;
    for (const auto& b : blocks_) all.insert(b.start);

    std::map<uint64_t, std::set<uint64_t>> dom;
    for (const auto& b : blocks_) {
        if (b.start == blockStart) dom[b.start] = {b.start};
        else dom[b.start] = all;
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& b : blocks_) {
            if (b.start == blockStart) continue;
            std::set<uint64_t> preds = predecessors(b.start);
            std::set<uint64_t> nd;
            bool first = true;
            for (uint64_t p : preds) {
                if (first) {
                    nd = dom[p];
                    first = false;
                } else {
                    std::set<uint64_t> inter;
                    for (uint64_t x : nd)
                        if (dom[p].count(x)) inter.insert(x);
                    nd.swap(inter);
                }
            }
            nd.insert(b.start);
            if (nd != dom[b.start]) {
                dom[b.start] = nd;
                changed = true;
            }
        }
    }
    return dom[blockStart];
}

std::string CfgBuilder::dot() const {
    std::string s = "digraph cfg {\n";
    char buf[64];
    for (const auto& b : blocks_) {
        std::snprintf(buf, sizeof(buf), "  L%llx [label=\"0x%llx\"];\n",
                      static_cast<unsigned long long>(b.start),
                      static_cast<unsigned long long>(b.start));
        s += buf;
        for (uint64_t t : b.succs) {
            std::snprintf(buf, sizeof(buf), "  L%llx -> L%llx;\n",
                          static_cast<unsigned long long>(b.start),
                          static_cast<unsigned long long>(t));
            s += buf;
        }
    }
    s += "}\n";
    return s;
}

} // namespace centrifuge
