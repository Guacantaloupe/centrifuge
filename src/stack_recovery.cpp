// centrifuge - Native Source Recovery Backend
// stack_recovery.cpp - stack frame analysis / slot recovery / promotion
#include "centrifuge/stack_recovery.hpp"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <limits>
#include <set>

namespace centrifuge {

namespace {

uint64_t stackPointerOffsetFor(const std::string& architecture) {
    if (architecture.rfind("x86", 0) == 0) return 4 * 8;
    if (architecture == "aarch64" || architecture == "arm64") return 31 * 8;
    return 2 * 8;
}

uint64_t framePointerOffsetFor(const std::string& architecture) {
    if (architecture.rfind("x86", 0) == 0) return 5 * 8; // rbp
    return 8 * 8; // riscv s0 / arm64 x29 (unused by default)
}

const Varnode* constVarnode(const PcodeInsn& pi, uint64_t id) {
    const Varnode* v = pi.find(id);
    return v && v->kind == Varnode::CONST ? v : nullptr;
}

bool registerVarnode(const PcodeInsn& pi, uint64_t id, uint64_t& offset) {
    const Varnode* v = pi.find(id);
    if (!v || v->kind != Varnode::REGISTER) return false;
    offset = v->offset;
    return true;
}

// integer type name for a byte width (only promoted widths)
std::string integerTypeName(int size) {
    switch (size) {
    case 1: return "uint8_t";
    case 2: return "uint16_t";
    case 4: return "uint32_t";
    case 8: return "uint64_t";
    default: return {};
    }
}

// Track stack-pointer updates inside a single p-code instruction.
// x86 p-code materialises "sp = sp - 8" as a unique temp followed by a
// COPY back into the sp register:
//   INT_SUB out=u in0=sp in1=8 ; *(u) = src ; COPY out=sp in0=u
// Only uniques that are copied back into sp (or write sp directly) move the
// stack pointer; uniques that merely compute sp+const addressing do not.
// spUniq maps every sp-carrying unique to its entry-relative bias; biasOut
// is the bias after the instruction.
void processSpOps(const PcodeInsn& insn, uint64_t spOffset, int64_t biasIn,
                  int64_t& biasOut,
                  std::map<uint64_t, int64_t>& spUniq) {
    biasOut = biasIn;
    uint64_t spRegId = 0;
    for (const auto& kv : insn.varnodes)
        if (kv.second.kind == Varnode::REGISTER &&
            kv.second.offset == spOffset) {
            spRegId = kv.first;
            break;
        }
    if (!spRegId) return;
    // uniques copied back into the sp register are sp moves
    std::set<uint64_t> copiedToSp;
    for (const PcodeOp& op : insn.ops) {
        if (op.op != POp::COPY || op.out != spRegId || !op.in0) continue;
        const Varnode* v = insn.find(op.in0);
        if (v && v->kind == Varnode::UNIQUE) copiedToSp.insert(op.in0);
    }
    auto spBias = [&](uint64_t id) -> int64_t* {
        if (id == spRegId) return &biasOut;
        const auto found = spUniq.find(id);
        return found == spUniq.end() ? nullptr : &found->second;
    };
    for (const PcodeOp& op : insn.ops) {
        if (!op.out) continue;
        const Varnode* out = insn.find(op.out);
        const bool uniqueOut = out && out->kind == Varnode::UNIQUE;
        if (op.op == POp::INT_SUB || op.op == POp::INT_ADD) {
            int64_t* base = spBias(op.in0);
            if (!base) continue;
            const Varnode* c = insn.find(op.in1);
            if (!c || c->kind != Varnode::CONST) continue;
            const int64_t k = static_cast<int64_t>(c->offset);
            const int64_t newBias =
                *base + (op.op == POp::INT_SUB ? -k : k);
            if (uniqueOut) {
                if (!copiedToSp.count(op.out)) continue; // pure addressing
                spUniq[op.out] = newBias;
                biasOut = newBias;
            } else {
                biasOut = newBias; // direct sp register write
            }
            continue;
        }
        if (op.op == POp::COPY && op.out == spRegId) {
            const auto found = spUniq.find(op.in0);
            if (found != spUniq.end()) biasOut = found->second;
        }
    }
}

} // namespace

std::string stackSlotName(int64_t offset) {
    if (offset < 0) return "local_m" + std::to_string(-offset);
    return "local_" + std::to_string(offset);
}

// ---------------------------------------------------------------------------
// Phase 1: prologue scan
// ---------------------------------------------------------------------------
bool StackFrameAnalysis::analyzePrologue(const CfgBlock& entry,
                                         int64_t& entryBiasOut) {
    int64_t bias = 0;
    bool sawFramePointer = false;
    int64_t frameBias = 0;
    std::vector<std::pair<uint64_t, int64_t>> saved;
    int64_t lastPrologueAddress = 0;

    for (const PcodeInsn& insn : entry.insns) {
        bool progressed = false;
        int64_t biasBefore = bias;
        int64_t biasOut = bias;
        std::map<uint64_t, int64_t> spUniq;
        processSpOps(insn, spOffset_, bias, biasOut, spUniq);
        bias = biasOut;
        for (const PcodeOp& op : insn.ops) {
            uint64_t outReg = 0;
            if (op.out && registerVarnode(insn, op.out, outReg)) {
                if (outReg == bpOffset_ && !sawFramePointer) {
                    // rbp = rsp  (or rbp = rsp + K via INT_ADD)
                    const Varnode* in0 = insn.find(op.in0);
                    if (in0 && in0->kind == Varnode::REGISTER &&
                        in0->offset == spOffset_) {
                        sawFramePointer = true;
                        frameBias = bias;
                        progressed = true;
                        if (op.op == POp::INT_ADD) {
                            const Varnode* c = constVarnode(insn, op.in1);
                            if (c) frameBias += static_cast<int64_t>(c->offset);
                        }
                    }
                }
            }
            if (op.op == POp::STORE) {
                // push-style save: address is the sp carrier itself
                int64_t slot = 0;
                bool isSpStore = false;
                const Varnode* addr = insn.find(op.in0);
                if (addr && addr->kind == Varnode::UNIQUE &&
                    spUniq.count(addr->id)) {
                    slot = spUniq[addr->id];
                    isSpStore = true;
                } else if (addr && addr->kind == Varnode::REGISTER &&
                           addr->offset == spOffset_) {
                    slot = bias;
                    isSpStore = true;
                }
                if (isSpStore && slot < 0) {
                    const Varnode* value = insn.find(op.in2);
                    if (value && value->kind == Varnode::REGISTER) {
                        saved.emplace_back(value->offset, slot);
                        progressed = true;
                    }
                }
            }
        }
        if (progressed) lastPrologueAddress = insn.addr;
        if (insn.kind == Insn::CALL || insn.kind == Insn::JCC ||
            insn.kind == Insn::RET || insn.kind == Insn::JMP)
            break;
        // stop at the first instruction that is not part of the prologue
        // (sp move, frame-pointer setup, or push-style sp store)
        bool prologueInsn = (bias != biasBefore);
        {
            int64_t probeOut = 0;
            std::map<uint64_t, int64_t> probeUniq;
            processSpOps(insn, spOffset_, bias, probeOut, probeUniq);
            if (probeOut != bias) prologueInsn = true;
            for (const PcodeOp& op : insn.ops) {
                uint64_t outReg = 0;
                if (op.out && registerVarnode(insn, op.out, outReg) &&
                    outReg == bpOffset_) {
                    const Varnode* in0 = insn.find(op.in0);
                    if (in0 && in0->kind == Varnode::REGISTER &&
                        in0->offset == spOffset_)
                        prologueInsn = true;
                }
                if (op.op == POp::STORE) {
                    const Varnode* addr = insn.find(op.in0);
                    if ((addr && addr->kind == Varnode::UNIQUE &&
                         probeUniq.count(addr->id)) ||
                        (addr && addr->kind == Varnode::REGISTER &&
                         addr->offset == spOffset_))
                        prologueInsn = true; // push-style store
                }
            }
        }
        if (!prologueInsn) break;
        if (bias < -64 * 1024) break; // sanity: absurd frame
    }

    model_.hasFramePointer = sawFramePointer;
    model_.frameBaseOffset = frameBias;
    model_.frameSize = std::max<int64_t>(0, -bias);
    model_.savedRegisters = std::move(saved);
    model_.prologueEnd = lastPrologueAddress;
    entryBiasOut = bias;
    stableSpBias_ = bias;
    return true;
}

// ---------------------------------------------------------------------------
// Address resolution
// ---------------------------------------------------------------------------
bool StackFrameAnalysis::resolveAddress(const PcodeInsn& pi, uint64_t addrId,
                                        int64_t bias, int64_t& slot,
                                        bool& viaFramePointer) const {
    const Varnode* v = pi.find(addrId);
    if (!v) return false;
    if (v->kind == Varnode::REGISTER) {
        if (v->offset == spOffset_) {
            viaFramePointer = false;
            slot = bias;
            return true;
        }
        if (model_.hasFramePointer && v->offset == bpOffset_) {
            viaFramePointer = true;
            slot = model_.frameBaseOffset;
            return true;
        }
        return false;
    }
    if (v->kind == Varnode::UNIQUE) {
        // find the defining op in this instruction
        for (const PcodeOp& op : pi.ops) {
            if (op.out != addrId) continue;
            if (op.op == POp::INT_ADD || op.op == POp::INT_SUB) {
                const Varnode* a = pi.find(op.in0);
                const Varnode* b = pi.find(op.in1);
                const Varnode* base = nullptr;
                const Varnode* c = nullptr;
                if (a && a->kind == Varnode::CONST && b) { base = b; c = a; }
                else if (b && b->kind == Varnode::CONST) { base = a; c = b; }
                else return false;
                int64_t baseSlot = 0;
                bool baseViaFp = false;
                if (!resolveAddress(pi, base->id, bias, baseSlot, baseViaFp))
                    return false;
                const int64_t k = static_cast<int64_t>(c->offset);
                slot = baseSlot + (op.op == POp::INT_SUB ? -k : k);
                viaFramePointer = baseViaFp;
                return true;
            }
            return false;
        }
    }
    return false;
}

bool StackFrameAnalysis::resolveSlot(const PcodeInsn& pi, uint64_t addrId,
                                     int64_t bias, int64_t& slot) const {
    bool viaFp = false;
    return resolveAddress(pi, addrId, bias, slot, viaFp);
}

int64_t StackFrameAnalysis::blockEntryBias(uint64_t blockStart) const {
    const auto found = blockSpBias_.find(blockStart);
    return found == blockSpBias_.end() ? stableSpBias_ : found->second;
}

// ---------------------------------------------------------------------------
// Phase 2: scan all blocks and collect stack accesses
// ---------------------------------------------------------------------------
void StackFrameAnalysis::scanBlock(const CfgBlock& block, int64_t entryBias,
                                   bool isEntry) {
    int64_t bias = entryBias;
    (void)isEntry;

    for (const PcodeInsn& insn : block.insns) {
        // -- sp updates (unique-carrier tracking) --
        int64_t biasOut = bias;
        std::map<uint64_t, int64_t> spUniq;
        processSpOps(insn, spOffset_, bias, biasOut, spUniq);
        bias = biasOut;

        // -- per-instruction address bookkeeping (UNIQUE ids are
        //    instruction-local) --
        std::map<uint64_t, int64_t> frameAddrSlot; // unique id -> slot
        for (const PcodeOp& op : insn.ops) {
            if ((op.op != POp::INT_ADD && op.op != POp::INT_SUB) ||
                !op.out)
                continue;
            const Varnode* out = insn.find(op.out);
            if (!out) continue;
            if (out->kind == Varnode::UNIQUE && spUniq.count(op.out))
                continue; // sp move, not an address
            int64_t slot = 0;
            bool viaFp = false;
            const bool in0ok =
                resolveAddress(insn, op.in0, bias, slot, viaFp);
            int64_t slot1 = 0;
            bool viaFp1 = false;
            const bool in1ok =
                resolveAddress(insn, op.in1, bias, slot1, viaFp1);
            if (!in0ok && !in1ok) continue;
            if (in0ok && !in1ok) {
                // in1 may be a plain constant offset: combine it
                const Varnode* b = insn.find(op.in1);
                if (b && b->kind == Varnode::CONST)
                    slot += (op.op == POp::INT_SUB
                                 ? -static_cast<int64_t>(b->offset)
                                 : static_cast<int64_t>(b->offset));
            } else if (!in0ok && in1ok) {
                slot = slot1;
                const Varnode* a = insn.find(op.in0);
                if (a && a->kind == Varnode::CONST)
                    slot += (op.op == POp::INT_SUB
                                 ? -static_cast<int64_t>(a->offset)
                                 : static_cast<int64_t>(a->offset));
            } else {
                // base + constant offset: combine when one side is a const
                const Varnode* a = insn.find(op.in0);
                const Varnode* b = insn.find(op.in1);
                if (a && a->kind == Varnode::CONST) {
                    slot = slot1 + (op.op == POp::INT_SUB
                                        ? -static_cast<int64_t>(a->offset)
                                        : static_cast<int64_t>(a->offset));
                } else if (b && b->kind == Varnode::CONST) {
                    slot = slot + (op.op == POp::INT_SUB
                                       ? -static_cast<int64_t>(b->offset)
                                       : static_cast<int64_t>(b->offset));
                }
                // else: base + non-constant index - keep the base slot
            }
            if (out->kind == Varnode::UNIQUE)
                frameAddrSlot[out->id] = slot;
            else if (out->kind == Varnode::REGISTER)
                markAddressTaken(slot); // lea-style: address escaped
        }

        // -- escaped address detection --
        std::set<uint64_t> escaped;
        for (const PcodeOp& op : insn.ops) {
            const bool addressOp = op.op == POp::LOAD ||
                                   op.op == POp::STORE;
            for (uint64_t input : {op.in0, op.in1, op.in2}) {
                if (!input) continue;
                if (!frameAddrSlot.count(input)) continue;
                if (addressOp && input == op.in0) continue;
                if (op.op == POp::INT_ADD || op.op == POp::INT_SUB)
                    continue; // derived address, handled below
                escaped.insert(input);
            }
            if (op.op == POp::COPY || op.op == POp::CALL ||
                op.op == POp::CALLIND || op.op == POp::RETURN) {
                for (uint64_t input : {op.in0, op.in1, op.in2}) {
                    if (!input || !frameAddrSlot.count(input)) continue;
                    const Varnode* out = insn.find(op.out);
                    if (op.op == POp::COPY && out &&
                        out->kind == Varnode::REGISTER &&
                        out->offset == spOffset_)
                        continue; // sp move back, not an escape
                    if (op.op == POp::COPY && out &&
                        out->kind == Varnode::REGISTER) {
                        // lea-style: address value escaped into a register
                        markAddressTaken(frameAddrSlot[input]);
                        continue;
                    }
                    escaped.insert(input);
                }
            }
        }

        // -- record accesses --
        for (const PcodeOp& op : insn.ops) {
            if (op.op != POp::LOAD && op.op != POp::STORE) continue;
            int64_t slot = 0;
            const Varnode* addr = insn.find(op.in0);
            if (addr && addr->kind == Varnode::UNIQUE &&
                spUniq.count(addr->id)) {
                slot = spUniq[addr->id]; // e.g. push's store target
            } else if (!resolveSlot(insn, op.in0, bias, slot)) {
                continue;
            }
            const bool escapedAddr =
                addr && addr->kind == Varnode::UNIQUE &&
                escaped.count(addr->id);
            const int size = [&]() {
                if (op.op == POp::STORE) {
                    const Varnode* v = insn.find(op.in2);
                    return v ? v->size : 0;
                }
                const Varnode* v = insn.find(op.out);
                return v ? v->size : 0;
            }();
            auto found = model_.slotIndexByOffset.find(slot);
            StackSlot* ss = nullptr;
            if (found == model_.slotIndexByOffset.end()) {
                model_.slots.push_back(StackSlot{});
                ss = &model_.slots.back();
                ss->offset = slot;
                ss->size = size;
                model_.slotIndexByOffset[slot] = model_.slots.size() - 1;
            } else {
                ss = &model_.slots[found->second];
            }
            if (op.op == POp::STORE) ss->writeSites.insert(insn.addr);
            else ss->readSites.insert(insn.addr);
            ss->firstAccess = std::min(ss->firstAccess, (int64_t)insn.addr);
            ss->lastAccess = std::max(ss->lastAccess, (int64_t)insn.addr);
            if (size > 0) ss->widths.insert(size);
            if (escapedAddr) ss->addressTaken = true;
        }
    }
    blockSpBias_[block.start] = bias;
}

// ---------------------------------------------------------------------------
// Role classification / overlap detection / promotion
// ---------------------------------------------------------------------------
void StackFrameAnalysis::classifyRoles() {
    std::set<int64_t> savedSlots;
    for (const auto& saved : model_.savedRegisters)
        savedSlots.insert(saved.second);
    for (StackSlot& slot : model_.slots) {
        if (slot.offset == 0) {
            slot.role = StackSlotRole::RETURN_ADDRESS;
        } else if (slot.offset > 0) {
            slot.role = StackSlotRole::PARAMETER;
        } else if (savedSlots.count(slot.offset)) {
            slot.role = StackSlotRole::SAVED_REGISTER;
        } else {
            slot.role = StackSlotRole::LOCAL;
        }
    }
}

void StackFrameAnalysis::detectOverlaps() {
    std::vector<size_t> locals;
    for (size_t i = 0; i < model_.slots.size(); ++i)
        if (model_.slots[i].role == StackSlotRole::LOCAL)
            locals.push_back(i);
    for (size_t i = 0; i < locals.size(); ++i) {
        for (size_t j = i + 1; j < locals.size(); ++j) {
            const StackSlot& a = model_.slots[locals[i]];
            const StackSlot& b = model_.slots[locals[j]];
            if (a.offset == b.offset) continue; // same slot, not overlap
            const int64_t aEnd = a.offset + (a.size > 0 ? a.size : 1);
            const int64_t bEnd = b.offset + (b.size > 0 ? b.size : 1);
            if (a.offset < bEnd && b.offset < aEnd) {
                model_.slots[locals[i]].overlaps = true;
                model_.slots[locals[i]].overlapWith = b.offset;
                model_.slots[locals[j]].overlaps = true;
                model_.slots[locals[j]].overlapWith = a.offset;
            }
        }
    }
}

void StackFrameAnalysis::promoteVariables() {
    for (StackSlot& slot : model_.slots) {
        if (slot.role != StackSlotRole::LOCAL) continue;
        if (slot.addressTaken || slot.overlaps) continue;
        if (slot.widths.size() != 1) continue; // mixed-width: keep fallback
        const int size = *slot.widths.begin();
        if (size < 1 || size > 8 || (size & (size - 1)) != 0) continue;
        const std::string type = integerTypeName(size);
        if (type.empty()) continue;
        slot.promoted = true;
        slot.variableName = stackSlotName(slot.offset);
        slot.typeName = type;
        slot.size = size;
        ++model_.promotedCount;
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------
void StackFrameAnalysis::markAddressTaken(int64_t slot) {
    auto found = model_.slotIndexByOffset.find(slot);
    if (found != model_.slotIndexByOffset.end()) {
        model_.slots[found->second].addressTaken = true;
        return;
    }
    // The address escaped before any direct access; create the slot so the
    // promotion pass sees it and keeps it un-promoted.
    model_.slots.push_back(StackSlot{});
    StackSlot& ss = model_.slots.back();
    ss.offset = slot;
    ss.addressTaken = true;
    model_.slotIndexByOffset[slot] = model_.slots.size() - 1;
}

bool StackFrameAnalysis::analyze(const CfgBuilder& cfg,
                                 const std::string& architecture) {
    model_ = StackFrameModel{};
    model_.architecture = architecture;
    spOffset_ = stackPointerOffsetFor(architecture);
    bpOffset_ = framePointerOffsetFor(architecture);
    model_.pointerSize = 8;
    if (architecture.rfind("x86", 0) == 0 &&
        architecture.find("win64") != std::string::npos)
        model_.shadowSpaceBytes = 0x20;

    const std::vector<CfgBlock>& blocks = cfg.blocks();
    if (blocks.empty()) return false;
    const CfgBlock& entry = blocks.front();
    model_.functionAddress = entry.start;

    int64_t entryBias = 0;
    analyzePrologue(entry, entryBias);

    for (const CfgBlock& block : blocks) {
        const bool isEntry = block.start == entry.start;
        const int64_t bias =
            isEntry ? 0 : blockEntryBias(block.start);
        scanBlock(block, bias, isEntry);
    }

    classifyRoles();
    detectOverlaps();
    promoteVariables();
    return true;
}

} // namespace centrifuge
