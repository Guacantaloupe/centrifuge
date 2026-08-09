// centrifuge - function-level SSA, type, ABI, and optimization analysis
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"

namespace centrifuge {

enum class TypeKind {
    UNKNOWN,
    BOOL,
    UNSIGNED_INT,
    SIGNED_INT,
    POINTER,
    FLOAT,
    VECTOR,
    MEMORY,
    VOID_TYPE,
};

struct DataType {
    TypeKind kind = TypeKind::UNKNOWN;
    int bits = 0;
    int lanes = 1;
    bool operator==(const DataType& other) const {
        return kind == other.kind && bits == other.bits && lanes == other.lanes;
    }
    bool operator!=(const DataType& other) const { return !(*this == other); }
    std::string name() const;
};

using SsaId = uint64_t;

struct SsaValue {
    enum Storage { CONSTANT, REGISTER, TEMPORARY, MEMORY_STATE } storage = TEMPORARY;
    SsaId id = 0;
    uint64_t offset = 0;
    int size = 0;
    uint32_t version = 0;
    std::string name;
    DataType type;
    std::optional<uint64_t> constant;
};

struct SsaOp {
    POp op = POp::UNIMPLEMENTED;
    SsaId output = 0;
    std::vector<SsaId> inputs;
    uint64_t address = 0;
    bool phi = false;
    bool removed = false;
};

struct SsaBlock {
    uint64_t start = 0;
    std::vector<uint64_t> predecessors;
    std::vector<uint64_t> successors;
    std::vector<SsaOp> phis;
    std::vector<SsaOp> ops;
};

struct FunctionParameter {
    std::string name;
    uint64_t registerOffset = 0;
    SsaId value = 0;
    DataType type;
};

struct FunctionSignature {
    std::vector<FunctionParameter> parameters;
    DataType returnType{TypeKind::VOID_TYPE, 0, 1};
    std::vector<SsaId> returnValues;
    bool variadic = false;
    std::string declaration(const std::string& name) const;
};

class FunctionIR {
public:
    bool build(const CfgBuilder& cfg, const std::string& architecture,
               const std::string& callingConvention = {});
    void inferTypes();
    FunctionSignature inferSignature() const;
    void optimize();

    const std::vector<SsaBlock>& blocks() const { return blocks_; }
    const std::map<SsaId, SsaValue>& values() const { return values_; }
    const SsaValue* value(SsaId id) const;
    size_t phiCount() const;
    size_t liveOpCount() const;
    std::string dump() const;

private:
    std::string arch_;
    std::string callingConvention_;
    std::vector<SsaBlock> blocks_;
    std::map<uint64_t, size_t> blockIndex_;
    std::map<SsaId, SsaValue> values_;
    std::map<uint64_t, std::map<std::pair<uint64_t, int>, SsaId>> outgoing_;
    std::map<std::pair<uint64_t, int>, SsaId> parameters_;
    SsaId nextId_ = 1;
};

struct JumpTable {
    uint64_t dispatchAddress = 0;
    uint64_t tableAddress = 0;
    int entrySize = 0;
    bool relative = false;
    std::vector<uint64_t> targets;
};

std::vector<JumpTable> recoverJumpTables(const CfgBuilder& cfg,
                                         const MemoryImage& memory,
                                         int pointerSize = 8,
                                         size_t maxEntries = 256);

} // namespace centrifuge
