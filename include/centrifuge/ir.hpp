// centrifuge - function-level SSA, type, ABI, and optimization analysis
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/analysis.hpp"
#include "centrifuge/cpp_recovery.hpp"

namespace centrifuge {

class ImportPrototypeRecovery; // defined in import_prototype.hpp

enum class TypeKind {
    UNKNOWN,
    BOOL,
    UNSIGNED_INT,
    SIGNED_INT,
    POINTER,
    FLOAT,
    VECTOR,
    ARRAY,
    STRUCT,
    UNION,
    FUNCTION_POINTER,
    MEMORY,
    VOID_TYPE,
};

struct TypeDetail;

struct DataType {
    TypeKind kind = TypeKind::UNKNOWN;
    int bits = 0;
    int lanes = 1;
    std::shared_ptr<TypeDetail> detail;
    DataType() = default;
    DataType(TypeKind kindValue, int bitCount, int laneCount = 1)
        : kind(kindValue), bits(bitCount), lanes(laneCount) {}
    bool operator==(const DataType& other) const {
        return kind == other.kind && bits == other.bits && lanes == other.lanes &&
               ((!detail && !other.detail) ||
                (detail && other.detail && detail == other.detail));
    }
    bool operator!=(const DataType& other) const { return !(*this == other); }
    std::string name() const;
    std::string declaration(const std::string& identifier) const;
};

struct TypeField {
    std::string name;
    uint64_t byteOffset = 0;
    DataType type;
};

struct TypeDetail {
    std::string name;
    std::vector<TypeField> fields;
    std::shared_ptr<DataType> elementType;
    size_t elementCount = 0;
    std::shared_ptr<DataType> returnType;
    std::vector<DataType> parameterTypes;
    bool variadic = false;
};

using MidValueId = uint64_t;
using SsaId = MidValueId;

// ABI argument register offsets (offset = storage byte offset, name = slot
// name) for the supported calling conventions.  Win64: rcx/rdx/r8/r9;
// SystemV: rdi/rsi/rdx/rcx/r8/r9; RISC-V: a0-a7; AArch64: x0-x7.
std::vector<std::pair<uint64_t, std::string>> abiArguments(
    const std::string& architecture,
    const std::string& callingConvention = {});

// Merge two observed types conservatively (widest kind-compatible shape).
DataType mergeType(DataType a, DataType b);

struct MidValue {
    enum Storage { CONSTANT, REGISTER, TEMPORARY, MEMORY_STATE } storage = TEMPORARY;
    SsaId id = 0;
    uint64_t offset = 0;
    int size = 0;
    uint32_t version = 0;
    std::string name;
    DataType type;
    std::optional<uint64_t> constant;
};
using SsaValue = MidValue;

enum class MidOperationClass {
    PHI,
    PURE,
    MEMORY_READ,
    MEMORY_WRITE,
    CALL,
    TERMINATOR,
};

struct MidInstruction {
    POp op = POp::UNIMPLEMENTED;
    SsaId output = 0;
    std::vector<SsaId> inputs;
    uint64_t address = 0;
    bool phi = false;
    bool removed = false;
    uint32_t memoryPartition = 0;
    uint32_t memoryVersionIn = 0;
    uint32_t memoryVersionOut = 0;
};
using SsaOp = MidInstruction;

struct MidBlock {
    uint64_t start = 0;
    std::vector<uint64_t> predecessors;
    std::vector<uint64_t> successors;
    std::vector<SsaOp> phis;
    std::vector<SsaOp> ops;
    std::map<uint32_t, uint32_t> memoryPhis;
};
using SsaBlock = MidBlock;

MidOperationClass classifyMidOperation(const MidInstruction& operation);

struct MidIRVerification {
    std::vector<std::string> errors;
    bool valid() const { return errors.empty(); }
};

enum class MemoryObjectKind { UNKNOWN, STACK, GLOBAL, HEAP, PARAMETER };

struct MemoryObject {
    uint64_t id = 0;
    MemoryObjectKind kind = MemoryObjectKind::UNKNOWN;
    uint64_t address = 0;
    uint64_t size = 0;
    MidValueId value = 0;
    uint64_t allocationSite = 0;
    std::string name;
};

struct MemoryPartition {
    uint32_t id = 0;
    MemoryObjectKind kind = MemoryObjectKind::UNKNOWN;
    uint64_t object = 0;
    int64_t byteOffset = 0;
    uint64_t byteSize = 0;
    std::string fieldPath;
};

class MidIR {
public:
    const std::vector<MidBlock>& blocks() const { return blocks_; }
    const std::map<MidValueId, MidValue>& values() const { return values_; }
    const MidValue* value(MidValueId id) const;
    const std::string& architecture() const { return arch_; }
    size_t phiCount() const;
    size_t liveOpCount() const;
    std::string dump() const;
    MidIRVerification verify() const;
    uint64_t addMemoryObject(MemoryObject object);
    void partitionMemory();
    const std::map<uint64_t, MemoryObject>& memoryObjects() const {
        return memoryObjects_;
    }
    const std::map<uint32_t, MemoryPartition>& memoryPartitions() const {
        return memoryPartitions_;
    }

protected:
    std::string arch_;
    std::vector<MidBlock> blocks_;
    std::map<uint64_t, size_t> blockIndex_;
    std::map<MidValueId, MidValue> values_;
    std::map<uint64_t, MemoryObject> memoryObjects_;
    std::map<uint32_t, MemoryPartition> memoryPartitions_;
    uint64_t nextMemoryObject_ = 1;
};

enum class AliasResult { NO_ALIAS, MAY_ALIAS, PARTIAL_ALIAS, MUST_ALIAS };

struct MemoryLocation {
    MemoryObjectKind kind = MemoryObjectKind::UNKNOWN;
    MidValueId object = 0;
    int64_t byteOffset = 0;
    uint64_t byteSize = 0;
    bool precise = false;
    std::string fieldPath;
};

class AliasAnalysis {
public:
    explicit AliasAnalysis(const MidIR& ir);
    MemoryLocation location(MidValueId pointer, uint64_t byteSize = 0) const;
    AliasResult alias(MidValueId left, uint64_t leftSize,
                      MidValueId right, uint64_t rightSize) const;
    bool mayClobber(const MidInstruction& write,
                    const MidInstruction& read) const;

private:
    MemoryLocation resolve(MidValueId pointer,
                           std::set<MidValueId>& visiting) const;
    const MidIR& ir_;
    std::map<MidValueId, const MidInstruction*> definitions_;
    mutable std::map<MidValueId, MemoryLocation> resolvedLocations_;
};

struct FunctionParameter {
    std::string name;
    uint64_t registerOffset = 0;
    SsaId value = 0;
    DataType type;
    bool onStack = false;
    int64_t stackOffset = 0;
};

struct FunctionSignature {
    std::vector<FunctionParameter> parameters;
    DataType returnType{TypeKind::VOID_TYPE, 0, 1};
    std::vector<SsaId> returnValues;
    bool variadic = false;
    bool hiddenSret = false;
    std::vector<DataType> returnComponents;
    std::string declaration(const std::string& name) const;
};

class FunctionIR : public MidIR {
public:
    bool build(const CfgBuilder& cfg, const std::string& architecture,
               const std::string& callingConvention = {});
    void inferTypes();
    // WS8 IR feedback: seed value types from refined whole-program
    // signatures before inferTypes, so interprocedural results change the
    // IR itself - own parameter entry values take the refined parameter
    // types, and call-result values take the refined callee return types.
    // mergeType keeps every seed an upgrade; inferTypes then propagates
    // the seeds through the whole function.
    void seedSignatureTypes(
        const FunctionSignature* ownSignature,
        const std::map<uint64_t, FunctionSignature>& calleeSignatures);
    FunctionSignature inferSignature() const;
    void optimize();
    // WS3: struct/union layouts recovered for call-result SSA values, keyed
    // by call instruction address.  Lets the emitter type a local holding a
    // call result (e.g. allocator-style factories) for member-access
    // naming without re-running the analysis.
    const std::map<uint64_t, DataType>& callResultTypes() const {
        return callResultTypes_;
    }

private:
    std::map<uint64_t, DataType> callResultTypes_;
    std::string callingConvention_;
    std::map<uint64_t, std::map<std::pair<uint64_t, int>, SsaId>> outgoing_;
    std::map<std::pair<uint64_t, int>, SsaId> parameters_;
    std::map<int64_t, SsaId> stackInputs_;
    bool hasTailCall_ = false;
    SsaId nextId_ = 1;

public:
    // Calling-convention recovery reads the entry-parameter and stack-input
    // maps that FunctionIR::build derives during renaming.
    const std::map<std::pair<uint64_t, int>, SsaId>& parameters() const {
        return parameters_;
    }
    const std::map<int64_t, SsaId>& stackInputs() const {
        return stackInputs_;
    }
    // Block-exit register states: {block start -> {register key -> SsaId}}.
    // The RETURN-block exit state carries the machine return value (RAX on
    // x86) even though the x86 `ret` p-code has no explicit operand.
    const std::map<uint64_t,
                   std::map<std::pair<uint64_t, int>, SsaId>>&
    outgoing() const {
        return outgoing_;
    }
};

// JumpTable lives in cfg.hpp (CfgBuilder consumes it); pulled in above.
std::vector<JumpTable> recoverJumpTables(const CfgBuilder& cfg,
                                         const MemoryImage& memory,
                                         int pointerSize = 8,
                                         size_t maxEntries = 256);

enum class ModRefInfo { NO_ACCESS, REF, MOD, MOD_REF, UNKNOWN };

struct FunctionEffects {
    bool readsMemory = false;
    bool writesMemory = false;
    bool allocates = false;
    bool frees = false;
    bool unknownCall = false;
    std::set<MemoryObjectKind> referencedObjects;
    std::set<MemoryObjectKind> modifiedObjects;
    // Whole-program Memory/Object analysis (WS8): concrete global-object
    // addresses this function provably reads or writes, resolved from the
    // memory partitions of its LOAD/STORE operations.  Propagated
    // interprocedurally by the Mod/Ref fixed point in ProgramAnalysis::build
    // (mergeFrom unions the sets), so a caller inherits every global its
    // callees touch, transitively, across recursion.
    std::set<uint64_t> referencedGlobals;
    std::set<uint64_t> modifiedGlobals;
    // MAY-attribution through pointer parameters (WS8): globals this
    // function may read/write because a pointer parameter it dereferences
    // may alias them (see AnalyzedFunction::paramPointsTo).  Kept separate
    // from the provable sets above: these edges carry lower confidence in
    // the knowledge graph.
    std::set<uint64_t> mayReferencedGlobals;
    std::set<uint64_t> mayModifiedGlobals;
    ModRefInfo modRef() const {
        if (unknownCall) return ModRefInfo::UNKNOWN;
        if (readsMemory && writesMemory) return ModRefInfo::MOD_REF;
        if (writesMemory) return ModRefInfo::MOD;
        if (readsMemory) return ModRefInfo::REF;
        return ModRefInfo::NO_ACCESS;
    }
    bool mergeFrom(const FunctionEffects& other);
};

struct CallSiteArgInfo {
    bool observed = false;
    int widthBytes = 0;
    DataType type; // inferred from the SSA value at the call site
    bool addressUsed = false; // value feeds a LOAD/STORE address
    bool constant = false;
    uint64_t constantValue = 0;
    // Interprocedural reverse evidence (WS8): index into the caller's own
    // ABI parameters when this argument value is the parameter forwarded
    // through a copy/zext/sext chain (-1 = not parameter-derived).  Lets a
    // pointer type recovered at the callee propagate back into the
    // caller's signature during the Phase 7 fixed point.
    int forwardedParam = -1;
    // Interprocedural return evidence (WS8): when this argument value is
    // the result of another call (through copy chains), the producer
    // callee's address - a POINTER parameter receiving the value proves
    // the producer returns a pointer.
    uint64_t fromCallResult = 0;
};

struct AnalyzedCallSite {
    uint64_t address = 0;
    std::optional<uint64_t> target;
    std::vector<std::optional<uint64_t>> arguments;
    // Per-ABI-register argument observations (index i matches
    // abiArguments(arch)[i]).  Only present when the caller's SSA value was
    // observable.
    std::vector<CallSiteArgInfo> argInfo;
    // How the call's return value is consumed by the caller.
    bool returnsValue = false;
    bool returnDereferenced = false; // result feeds a LOAD/STORE address
    bool returnArithmetic = false;   // result feeds integer arithmetic
    bool returnBoolean = false;      // result feeds a conditional
    int returnWidthBytes = 0;
    bool indirect = false;
};

struct AnalyzedFunction {
    Function function;
    FunctionSignature signature;
    std::vector<uint64_t> callers;
    std::vector<uint64_t> callees;
    std::vector<AnalyzedCallSite> callSites;
    size_t blocks = 0;
    size_t phiNodes = 0;
    size_t liveOperations = 0;
    FunctionEffects effects;
    // WS3: struct/union layouts recovered for call results (call address ->
    // aggregate type), used for member-access naming on locals.
    std::map<uint64_t, DataType> callResultTypes;
    // WS8 Memory/Object analysis: points-to evidence per parameter
    // (register offset -> concrete global addresses callers pass as that
    // argument).  Only constants inside the program's data regions qualify,
    // so a set entry names a provable global object the parameter may
    // alias - the seed of the object/alias analysis.
    std::map<uint64_t, std::set<uint64_t>> paramPointsTo;
    // Register offsets of pointer parameters this function's body
    // dereferences: paramReadParams for LOADs, paramWrittenParams for
    // STOREs.  Combined with paramPointsTo this attributes
    // may-reads/may-writes to the pointed-to globals (WS8 fixed-point
    // feedback).
    std::set<uint64_t> paramReadParams;
    std::set<uint64_t> paramWrittenParams;
    bool complete = false;
    bool complexityLimited = false;
    std::string incompleteReason;
};

// Whole-program orchestration over function discovery, CFG/SSA construction,
// signature recovery and direct-call graph propagation.
class ProgramAnalysis {
public:
    bool build(const Program& program, const SleighEngine& engine,
               const std::string& callingConvention = {},
               size_t maximumFunctions = 0);
    // One analysis round (WS8): function discovery, CFG/SSA construction,
    // signature recovery and every whole-program fixed point.  Invoked by
    // build() until the signature set reaches a fixed point.
    bool buildPipeline(const Program& program, const SleighEngine& engine,
                       const std::string& callingConvention,
                       size_t maximumFunctions);
    const std::map<uint64_t, AnalyzedFunction>& functions() const {
        return functions_;
    }
    const AnalyzedFunction* functionAt(uint64_t address) const;
    std::optional<FunctionSignature> signatureAt(uint64_t address) const;
    // Call-site-recovered prototypes for DLL imports (Phase 6).
    const ImportPrototypeRecovery& importPrototypes() const;
    std::optional<FunctionEffects> effectsAt(uint64_t address) const;
    const CppRecoveryResult& cppTypes() const { return cppTypes_; }
    std::string decompileFunction(const Program& program,
                                  const SleighEngine& engine,
                                  uint64_t address) const;

private:
    std::string architecture_;
    std::string callingConvention_;
    std::map<uint64_t, AnalyzedFunction> functions_;
    std::unique_ptr<ImportPrototypeRecovery> importPrototypes_;
    // WS8 IR feedback: refined signatures from the previous analysis round,
    // seeded into each rebuilt FunctionIR (see seedSignatureTypes).  Empty
    // on the first round.
    std::map<uint64_t, FunctionSignature> seedSignatures_;

public:
    ~ProgramAnalysis();
    CppRecoveryResult cppTypes_;
};

} // namespace centrifuge
