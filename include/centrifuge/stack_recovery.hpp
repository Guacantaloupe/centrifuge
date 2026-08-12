// centrifuge - Native Source Recovery Backend
//
// Phase 1-3 of the Decompiler roadmap:
//   Phase 1: StackFrameAnalysis   - recover the per-function stack frame
//                                    (frame size, base, prologue/epilogue,
//                                    saved registers, parameter/local areas)
//   Phase 2: StackSlotRecovery    - lift provably-stable stack accesses into
//                                    StackSlot IR objects (offset, width,
//                                    read/write sites, lifetime)
//   Phase 3: VariablePromotion    - promote safe stack slots to source-level
//                                    local variables (local_N)
//
// The analysis operates on the p-code CFG (CfgBuilder), never on generated
// C++ text.  Anything that cannot be proven safe stays a raw memory
// operation and the existing Machine Semantic Backend output is preserved.
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"

namespace centrifuge {

enum class StackSlotRole {
    UNKNOWN,
    LOCAL,          // function-local variable area
    SAVED_REGISTER, // nonvolatile register saved by the prologue
    PARAMETER,      // stack argument above the entry stack pointer
    RETURN_ADDRESS, // the return-address slot at entry rsp
    SHADOW_SPACE,   // Windows x64 shadow space below a call site
    COOKIE,         // GS security cookie slot
};

// A single recovered stack slot, keyed by its byte offset relative to the
// entry stack pointer (negative offsets live in the local area).
struct StackSlot {
    int64_t offset = 0;         // byte offset relative to entry rsp
    int size = 0;               // access width in bytes (0 = unknown)
    StackSlotRole role = StackSlotRole::UNKNOWN;
    std::set<uint64_t> readSites;   // instruction addresses that read it
    std::set<uint64_t> writeSites;  // instruction addresses that write it
    int64_t firstAccess = INT64_MAX;
    int64_t lastAccess = INT64_MIN;
    bool addressTaken = false;  // address escaped (lea / passed as value)
    bool promoted = false;      // promoted to a source-level variable
    std::string variableName;   // "local_N" once promoted
    std::string typeName;       // "uint32_t" etc. once promoted
    std::set<int> widths;       // distinct access widths observed
    bool overlaps = false;      // overlaps another slot (never promote)
    int64_t overlapWith = 0;    // offset of the overlapping slot
};

// The per-function stack frame model produced by StackFrameAnalysis.
struct StackFrameModel {
    uint64_t functionAddress = 0;
    std::string architecture;
    int64_t frameSize = 0;        // bytes allocated below the entry rsp
    int64_t frameBaseOffset = 0;  // frame-base (rbp) bias vs entry rsp
    bool hasFramePointer = false; // function establishes a frame pointer
    int pointerSize = 8;
    int64_t prologueEnd = 0;      // address of the last prologue instruction
    std::vector<StackSlot> slots;
    std::map<int64_t, size_t> slotIndexByOffset;
    std::vector<std::pair<uint64_t, int64_t>> savedRegisters; // (reg, slot off)
    int64_t shadowSpaceBytes = 0;
    size_t promotedCount = 0;

    const StackSlot* slotAt(int64_t offset) const {
        const auto found = slotIndexByOffset.find(offset);
        return found == slotIndexByOffset.end() ? nullptr
                                                : &slots[found->second];
    }
};

// Phase 1-3 analysis driver.  Build the model from a p-code CFG.
class StackFrameAnalysis {
public:
    // architecture strings follow the existing convention ("x86-64-win64").
    bool analyze(const CfgBuilder& cfg, const std::string& architecture);

    const StackFrameModel& model() const { return model_; }

    // Resolve an address varnode to a frame-relative slot offset.  `bias` is
    // the current rsp bias relative to the entry stack pointer.  Returns
    // false when the address cannot be proven frame-relative.
    bool resolveSlot(const PcodeInsn& pi, uint64_t addrId, int64_t bias,
                     int64_t& slot) const;

    // rsp bias at the entry of a block (assumes the stable post-prologue
    // value for non-entry blocks; see implementation notes).
    int64_t blockEntryBias(uint64_t blockStart) const;

private:
    StackFrameModel model_;
    uint64_t spOffset_ = 32; // x86 rsp register offset
    uint64_t bpOffset_ = 40; // x86 rbp register offset
    int64_t stableSpBias_ = 0;
    std::map<uint64_t, int64_t> blockSpBias_;

    bool analyzePrologue(const CfgBlock& entry, int64_t& entryBiasOut);
    void scanBlock(const CfgBlock& block, int64_t entryBias, bool isEntry);
    bool resolveAddress(const PcodeInsn& pi, uint64_t addrId, int64_t bias,
                        int64_t& slot, bool& viaFramePointer) const;
    void markAddressTaken(int64_t slot);
    void classifyRoles();
    void detectOverlaps();
    void promoteVariables();
};

// Convenience: name for a stack slot relative to the frame, matching the
// existing emitter convention ("local_m20" / "local_20").
std::string stackSlotName(int64_t offset);

} // namespace centrifuge
