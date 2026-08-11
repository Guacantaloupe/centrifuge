// centrifuge - a Ghidra reimplementation in C++17
// cfg.cpp - control-flow graph construction + dominators
#include "centrifuge/cfg.hpp"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <map>
#include <set>

namespace centrifuge {

bool CfgBuilder::build(
    const SleighEngine& eng,
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t start,
    uint64_t end, const std::function<bool(uint64_t)>& isExecutable) {
    blocks_.clear();
    idx_.clear();
    loops_.clear();
    entry_ = start;

    if (end != 0 && start >= end) return false;

    // Phase 1: discover the reachable instruction graph. Keeping this at
    // instruction granularity lets us collect every leader before blocks are
    // formed, including targets that point into a previously explored run.
    std::map<uint64_t, PcodeInsn> insns;
    std::map<uint64_t, std::vector<uint64_t>> flow;
    std::map<uint64_t, std::vector<uint64_t>> calls;
    std::map<uint64_t, uint64_t> tailCalls;
    std::set<uint64_t> leaders{start};
    std::vector<uint64_t> worklist{start};

    auto readable = [&](uint64_t addr) {
        uint8_t byte = 0;
        return (!isExecutable || isExecutable(addr)) && read(addr, &byte, 1);
    };
    auto inFunction = [&](uint64_t addr) {
        return end == 0 || (addr >= start && addr < end);
    };
    auto addUnique = [](std::vector<uint64_t>& values, uint64_t value) {
        if (std::find(values.begin(), values.end(), value) == values.end())
            values.push_back(value);
    };
    auto enqueue = [&](uint64_t from, uint64_t target, bool leader) {
        if (!inFunction(target) || !readable(target)) return false;
        addUnique(flow[from], target);
        if (leader) leaders.insert(target);
        if (!insns.count(target)) worklist.push_back(target);
        return true;
    };

    while (!worklist.empty()) {
        const uint64_t a = worklist.back();
        worklist.pop_back();
        if (insns.count(a) || !inFunction(a) || !readable(a)) continue;

        PcodeInsn pi;
        std::string err;
        if (!eng.disassemble(read, a, pi, err) || pi.size <= 0 ||
            static_cast<uint64_t>(pi.size) >
                std::numeric_limits<uint64_t>::max() - a)
            continue;

        const uint64_t next = a + static_cast<uint64_t>(pi.size);
        insns.emplace(a, pi);

        // An instruction constructor may contain a call followed by another
        // terminator (for example a compact test/spec intrinsic).  Record
        // direct call operations independently of the final instruction kind.
        for (const PcodeOp& operation : pi.ops) {
            if (operation.op != POp::CALL) continue;
            const Varnode* target = pi.find(operation.in0);
            if (target && target->isConst()) addUnique(calls[a], target->offset);
        }

        const bool traps = std::any_of(
            pi.ops.begin(), pi.ops.end(), [](const PcodeOp& operation) {
                return operation.op == POp::TRAP;
            });
        if (traps) continue;
        switch (pi.kind) {
        case Insn::RET:
            break;
        case Insn::JMP:
            if (pi.targetKnown && !enqueue(a, pi.target, true) && end != 0 &&
                !inFunction(pi.target))
                tailCalls.emplace(a, pi.target);
            break;
        case Insn::JCC:
            enqueue(a, next, true); // fallthrough stays first
            if (pi.targetKnown) enqueue(a, pi.target, true);
            break;
        case Insn::CALL:
            if (pi.targetKnown) addUnique(calls[a], pi.target);
            enqueue(a, next, false);
            break;
        case Insn::OTHER:
        case Insn::NOP:
            enqueue(a, next, false);
            break;
        }
    }

    if (!insns.count(start)) return false;

    // Phase 2: form maximal basic blocks using the complete leader set.
    std::set<uint64_t> assigned;
    for (uint64_t leader : leaders) {
        if (!insns.count(leader) || assigned.count(leader)) continue;
        CfgBlock block;
        block.start = leader;
        uint64_t cur = leader;
        for (;;) {
            auto it = insns.find(cur);
            if (it == insns.end() || assigned.count(cur)) break;
            const PcodeInsn& pi = it->second;
            block.insns.push_back(pi);
            assigned.insert(cur);
            block.end = cur + static_cast<uint64_t>(pi.size);

            auto callIt = calls.find(cur);
            if (callIt != calls.end())
                for (uint64_t target : callIt->second)
                    addUnique(block.calls, target);

            auto tailIt = tailCalls.find(cur);
            if (tailIt != tailCalls.end()) {
                block.tailCallTarget = tailIt->second;
                break;
            }

            const auto flowIt = flow.find(cur);
            const std::vector<uint64_t> noFlow;
            const auto& nexts = flowIt == flow.end() ? noFlow : flowIt->second;
            if (pi.kind == Insn::RET || pi.kind == Insn::JMP ||
                pi.kind == Insn::JCC || nexts.empty()) {
                for (uint64_t target : nexts)
                    if (leaders.count(target)) addUnique(block.succs, target);
                break;
            }

            const uint64_t next = nexts.front();
            if (leaders.count(next)) {
                addUnique(block.succs, next);
                break;
            }
            cur = next;
        }
        blocks_.push_back(std::move(block));
    }

    std::sort(blocks_.begin(), blocks_.end(),
              [](const CfgBlock& a, const CfgBlock& b) {
                  return a.start < b.start;
              });
    for (size_t i = 0; i < blocks_.size(); ++i) idx_[blocks_[i].start] = i;
    if (!blockAt(start)) return false;
    findNaturalLoops();
    return true;
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
    for (const auto& b : blocks_) {
        for (uint64_t s : b.succs)
            if (s == blockStart) p.insert(b.start);
        for (uint64_t s : b.exceptionSuccs)
            if (s == blockStart) p.insert(b.start);
    }
    return p;
}

std::set<uint64_t> CfgBuilder::dominators(uint64_t blockStart) const {
    if (!idx_.count(blockStart) || !idx_.count(entry_)) return {};
    // iterative dataflow: dom(b) = {b} ∪ ⋂ dom(p)
    std::set<uint64_t> all;
    for (const auto& b : blocks_) all.insert(b.start);

    std::map<uint64_t, std::set<uint64_t>> dom;
    for (const auto& b : blocks_) {
        if (b.start == entry_) dom[b.start] = {b.start};
        else dom[b.start] = all;
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& b : blocks_) {
            if (b.start == entry_) continue;
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
    return dom.at(blockStart);
}

void CfgBuilder::findNaturalLoops() {
    loops_.clear();
    std::map<uint64_t, size_t> byHeader;

    // Batch dominator dataflow: computing dominators(block) per tail made
    // this pass O(B^4) (each call re-ran the full iterative fixpoint over
    // every block).  Large 5.x Blender functions (27KB+) blew up to minutes.
    // Run the fixpoint once for the whole graph and look results up.
    // dom(b) = {b} ∪ ⋂_{p in preds(b)} dom(p); entry = {entry}.
    // Precompute the predecessor table once; predecessors() scanned every
    // block per call, adding another O(B) factor to every back-edge walk.
    std::map<uint64_t, std::vector<uint64_t>> preds;
    for (const auto& b : blocks_) {
        for (uint64_t s : b.succs) preds[s].push_back(b.start);
        for (uint64_t s : b.exceptionSuccs) preds[s].push_back(b.start);
    }

    std::map<uint64_t, std::set<uint64_t>> dom;
    if (!blocks_.empty() && idx_.count(entry_)) {
        std::set<uint64_t> all;
        for (const auto& b : blocks_) all.insert(b.start);
        for (const auto& b : blocks_) {
            if (b.start == entry_) dom[b.start] = {b.start};
            else dom[b.start] = all;
        }
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto& b : blocks_) {
                if (b.start == entry_) continue;
                std::set<uint64_t> nd;
                bool first = true;
                const auto predIt = preds.find(b.start);
                if (predIt != preds.end()) {
                    for (uint64_t p : predIt->second) {
                        const auto dit = dom.find(p);
                        if (dit == dom.end()) continue;
                        if (first) {
                            nd = dit->second;
                            first = false;
                        } else {
                            std::set<uint64_t> inter;
                            for (uint64_t x : nd)
                                if (dit->second.count(x)) inter.insert(x);
                            nd.swap(inter);
                        }
                    }
                }
                nd.insert(b.start);
                if (nd != dom[b.start]) {
                    dom[b.start] = nd;
                    changed = true;
                }
            }
        }
    }

    for (const auto& tail : blocks_) {
        const auto tailDomIt = dom.find(tail.start);
        static const std::set<uint64_t> kEmptyDom;
        const std::set<uint64_t>& tailDom =
            tailDomIt == dom.end() ? kEmptyDom : tailDomIt->second;
        for (uint64_t header : tail.succs) {
            if (!tailDom.count(header)) continue; // not a back edge

            size_t loopIndex = 0;
            auto found = byHeader.find(header);
            if (found == byHeader.end()) {
                loopIndex = loops_.size();
                byHeader.emplace(header, loopIndex);
                NaturalLoop loop;
                loop.header = header;
                loop.blocks.insert(header);
                loops_.push_back(std::move(loop));
            } else {
                loopIndex = found->second;
            }

            NaturalLoop& loop = loops_[loopIndex];
            loop.backEdges.emplace_back(tail.start, header);
            std::vector<uint64_t> worklist;
            if (loop.blocks.insert(tail.start).second && tail.start != header)
                worklist.push_back(tail.start);
            while (!worklist.empty()) {
                const uint64_t block = worklist.back();
                worklist.pop_back();
                const auto predIt = preds.find(block);
                if (predIt == preds.end()) continue;
                for (uint64_t pred : predIt->second) {
                    if (loop.blocks.insert(pred).second && pred != header)
                        worklist.push_back(pred);
                }
            }
        }
    }

    for (auto& loop : loops_) {
        for (uint64_t blockAddr : loop.blocks) {
            const CfgBlock* block = blockAt(blockAddr);
            if (!block) continue;
            for (uint64_t succ : block->succs)
                if (!loop.blocks.count(succ))
                    loop.exits.emplace_back(blockAddr, succ);
        }
        std::sort(loop.backEdges.begin(), loop.backEdges.end());
        loop.backEdges.erase(
            std::unique(loop.backEdges.begin(), loop.backEdges.end()),
            loop.backEdges.end());
        std::sort(loop.exits.begin(), loop.exits.end());
        loop.exits.erase(std::unique(loop.exits.begin(), loop.exits.end()),
                         loop.exits.end());
    }

    // The smallest strict superset is the immediate parent loop.
    for (auto& child : loops_) {
        const NaturalLoop* parent = nullptr;
        for (const auto& candidate : loops_) {
            if (candidate.header == child.header ||
                candidate.blocks.size() <= child.blocks.size())
                continue;
            if (!std::includes(candidate.blocks.begin(), candidate.blocks.end(),
                               child.blocks.begin(), child.blocks.end()))
                continue;
            if (!parent || candidate.blocks.size() < parent->blocks.size())
                parent = &candidate;
        }
        if (parent) child.parentHeader = parent->header;
    }

    std::sort(loops_.begin(), loops_.end(),
              [](const NaturalLoop& a, const NaturalLoop& b) {
                  return a.header < b.header;
              });
}

const NaturalLoop* CfgBuilder::loopByHeader(uint64_t header) const {
    for (const auto& loop : loops_)
        if (loop.header == header) return &loop;
    return nullptr;
}

const NaturalLoop* CfgBuilder::innermostLoopForBlock(uint64_t blockStart) const {
    const NaturalLoop* result = nullptr;
    for (const auto& loop : loops_) {
        if (!loop.blocks.count(blockStart)) continue;
        if (!result || loop.blocks.size() < result->blocks.size()) result = &loop;
    }
    return result;
}

void CfgBuilder::applyExceptionRegions(
    const std::vector<ExceptionRegion>& regions) {
    for (auto& block : blocks_) {
        block.exceptionSuccs.clear();
        for (const auto& region : regions) {
            if (!region.handlers.empty()) {
                for (const auto& handler : region.handlers) {
                    if (!handler.landingPad || block.end <= handler.start ||
                        block.start >= handler.end)
                        continue;
                    if (std::find(block.exceptionSuccs.begin(),
                                  block.exceptionSuccs.end(),
                                  handler.landingPad) == block.exceptionSuccs.end())
                        block.exceptionSuccs.push_back(handler.landingPad);
                }
            } else if (region.kind == ExceptionRegion::WINDOWS_UNWIND &&
                       region.handler && block.end > region.start &&
                       block.start < region.end &&
                       std::find(block.exceptionSuccs.begin(),
                                 block.exceptionSuccs.end(), region.handler) ==
                           block.exceptionSuccs.end()) {
                block.exceptionSuccs.push_back(region.handler);
            }
        }
        std::sort(block.exceptionSuccs.begin(), block.exceptionSuccs.end());
    }
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
        for (uint64_t t : b.calls) {
            std::snprintf(buf, sizeof(buf),
                          "  L%llx -> L%llx [style=dashed,label=\"call\"];\n",
                          static_cast<unsigned long long>(b.start),
                          static_cast<unsigned long long>(t));
            s += buf;
        }
        for (uint64_t t : b.exceptionSuccs) {
            std::snprintf(buf, sizeof(buf),
                          "  L%llx -> L%llx [style=dotted,color=red,label=\"exception\"];\n",
                          static_cast<unsigned long long>(b.start),
                          static_cast<unsigned long long>(t));
            s += buf;
        }
        if (b.tailCallTarget) {
            std::snprintf(buf, sizeof(buf),
                          "  L%llx -> L%llx [style=dashed,label=\"tail\"];\n",
                          static_cast<unsigned long long>(b.start),
                          static_cast<unsigned long long>(*b.tailCallTarget));
            s += buf;
        }
    }
    s += "}\n";
    return s;
}

} // namespace centrifuge
