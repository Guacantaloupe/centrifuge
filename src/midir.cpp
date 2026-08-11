// centrifuge - machine-independent SSA MidIR and alias analysis
#include "centrifuge/ir.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <tuple>

namespace centrifuge {
namespace {

bool isStackRegister(const std::string& architecture, uint64_t offset) {
    if (architecture.rfind("x86", 0) == 0)
        return offset == 4 * 8 || offset == 5 * 8;
    if (architecture.rfind("riscv", 0) == 0) return offset == 2 * 8;
    if (architecture == "aarch64" || architecture == "arm64")
        return offset == 31 * 8;
    return false;
}

uint64_t accessSize(const MidIR& ir, const MidInstruction& operation) {
    MidValueId valueId = 0;
    if (operation.op == POp::LOAD)
        valueId = operation.output;
    else if (operation.op == POp::STORE && operation.inputs.size() > 2)
        valueId = operation.inputs[2];
    const MidValue* value = ir.value(valueId);
    return value && value->size > 0 ? static_cast<uint64_t>(value->size) : 0;
}

} // namespace

MidOperationClass classifyMidOperation(const MidInstruction& operation) {
    if (operation.phi) return MidOperationClass::PHI;
    switch (operation.op) {
    case POp::LOAD: return MidOperationClass::MEMORY_READ;
    case POp::STORE: return MidOperationClass::MEMORY_WRITE;
    case POp::CALL:
    case POp::CALLIND: return MidOperationClass::CALL;
    case POp::BRANCH:
    case POp::CBRANCH:
    case POp::BRANCHIND:
    case POp::RETURN:
    case POp::TRAP: return MidOperationClass::TERMINATOR;
    case POp::SYSCALL: return MidOperationClass::CALL;
    default: return MidOperationClass::PURE;
    }
}

const MidValue* MidIR::value(MidValueId id) const {
    const auto found = values_.find(id);
    return found == values_.end() ? nullptr : &found->second;
}

size_t MidIR::phiCount() const {
    size_t count = 0;
    for (const MidBlock& block : blocks_) count += block.phis.size();
    return count;
}

size_t MidIR::liveOpCount() const {
    size_t count = 0;
    for (const MidBlock& block : blocks_)
        for (const MidInstruction& operation : block.ops)
            count += !operation.removed;
    return count;
}

std::string MidIR::dump() const {
    std::ostringstream output;
    for (const MidBlock& block : blocks_) {
        output << "block 0x" << std::hex << block.start << std::dec << ":\n";
        for (const auto& memoryPhi : block.memoryPhis)
            output << "  m" << memoryPhi.first << ".v" << memoryPhi.second
                   << " = MEMORY_PHI\n";
        auto print = [&](const MidInstruction& operation) {
            if (operation.removed) return;
            if (operation.output) output << "  v" << operation.output << " = ";
            else output << "  ";
            output << (operation.phi ? "PHI" : pOpName(operation.op)) << "(";
            for (size_t i = 0; i < operation.inputs.size(); ++i) {
                if (i) output << ", ";
                output << "v" << operation.inputs[i];
            }
            output << ")";
            if (operation.op == POp::LOAD || operation.op == POp::STORE ||
                operation.op == POp::CALL || operation.op == POp::CALLIND ||
                operation.op == POp::SYSCALL)
                output << " [m" << operation.memoryPartition << ".v"
                       << operation.memoryVersionIn << " -> v"
                       << operation.memoryVersionOut << "]";
            output << "\n";
        };
        for (const MidInstruction& phi : block.phis) print(phi);
        for (const MidInstruction& operation : block.ops) print(operation);
    }
    return output.str();
}

MidIRVerification MidIR::verify() const {
    MidIRVerification result;
    std::set<uint64_t> blockAddresses;
    std::set<MidValueId> definitions;
    for (const auto& entry : values_) {
        if (!entry.first || entry.second.id != entry.first)
            result.errors.push_back("value table contains an invalid or mismatched id");
    }
    for (const MidBlock& block : blocks_) {
        if (!blockAddresses.insert(block.start).second)
            result.errors.push_back("duplicate MidIR block at " +
                                    std::to_string(block.start));
        auto check = [&](const MidInstruction& operation, bool expectPhi) {
            if (operation.phi != expectPhi)
                result.errors.push_back("phi placement mismatch at " +
                                        std::to_string(operation.address));
            if (operation.output) {
                if (!value(operation.output))
                    result.errors.push_back("operation defines a missing MidIR value");
                if (!definitions.insert(operation.output).second)
                    result.errors.push_back("MidIR value has multiple definitions");
            }
            for (MidValueId input : operation.inputs)
                if (input && !value(input))
                    result.errors.push_back("operation uses a missing MidIR value");
            if (expectPhi && operation.inputs.size() != block.predecessors.size())
                result.errors.push_back("phi input count does not match predecessor count");
            if ((operation.op == POp::LOAD || operation.op == POp::STORE ||
                 operation.op == POp::CALL || operation.op == POp::CALLIND ||
                 operation.op == POp::SYSCALL) &&
                !memoryPartitions_.count(operation.memoryPartition))
                result.errors.push_back("memory operation references a missing partition");
            if ((operation.op == POp::STORE || operation.op == POp::CALL ||
                 operation.op == POp::CALLIND || operation.op == POp::SYSCALL) &&
                !operation.memoryVersionOut)
                result.errors.push_back("memory-writing operation has no MemorySSA version");
        };
        for (const auto& memoryPhi : block.memoryPhis)
            if (!memoryPartitions_.count(memoryPhi.first) || !memoryPhi.second)
                result.errors.push_back("invalid partitioned MemorySSA phi");
        for (const MidInstruction& phi : block.phis) check(phi, true);
        for (const MidInstruction& operation : block.ops) check(operation, false);
    }
    for (const auto& entry : values_) {
        const MidValue& valueEntry = entry.second;
        const bool entryValue = valueEntry.storage == MidValue::CONSTANT ||
                                valueEntry.version == 0;
        if (!entryValue && !definitions.count(entry.first))
            result.errors.push_back("non-entry MidIR value has no definition");
    }
    return result;
}

uint64_t MidIR::addMemoryObject(MemoryObject object) {
    if (!object.id) object.id = nextMemoryObject_++;
    else nextMemoryObject_ = std::max(nextMemoryObject_, object.id + 1);
    const uint64_t id = object.id;
    memoryObjects_[id] = std::move(object);
    return id;
}

void MidIR::partitionMemory() {
    memoryPartitions_.clear();
    MemoryPartition unknown;
    unknown.id = 0;
    unknown.kind = MemoryObjectKind::UNKNOWN;
    unknown.fieldPath = "unknown";
    memoryPartitions_[0] = unknown;

    AliasAnalysis aliases(*this);
    using PartitionKey = std::tuple<MemoryObjectKind, uint64_t, int64_t,
                                    uint64_t, std::string>;
    std::map<PartitionKey, uint32_t> ids;
    uint32_t nextPartition = 1;
    for (MidBlock& block : blocks_)
        for (MidInstruction& operation : block.ops) {
            operation.memoryPartition = 0;
            operation.memoryVersionIn = 0;
            operation.memoryVersionOut = 0;
            if ((operation.op != POp::LOAD && operation.op != POp::STORE) ||
                operation.inputs.empty())
                continue;
            const uint64_t size = accessSize(*this, operation);
            const MemoryLocation location = aliases.location(operation.inputs[0], size);
            if (!location.precise || location.kind == MemoryObjectKind::UNKNOWN)
                continue;
            const PartitionKey key{location.kind, location.object,
                                   location.byteOffset, size,
                                   location.fieldPath};
            auto inserted = ids.emplace(key, nextPartition);
            if (inserted.second) {
                MemoryPartition partition;
                partition.id = nextPartition++;
                partition.kind = location.kind;
                partition.object = location.object;
                partition.byteOffset = location.byteOffset;
                partition.byteSize = size;
                partition.fieldPath = location.fieldPath;
                memoryPartitions_[partition.id] = std::move(partition);
            }
            operation.memoryPartition = inserted.first->second;
        }

    // Assign stable versions to writes first.  Calls and unknown stores are
    // global barriers; a barrier version becomes the current version of every
    // known partition during the data-flow pass.
    uint32_t nextVersion = 1;
    for (MidBlock& block : blocks_)
        for (MidInstruction& operation : block.ops) {
            if (operation.op == POp::STORE || operation.op == POp::CALL ||
                operation.op == POp::CALLIND || operation.op == POp::SYSCALL)
                operation.memoryVersionOut = nextVersion++;
        }

    std::map<uint64_t, std::map<uint32_t, uint32_t>> outgoing;
    std::map<std::pair<uint64_t, uint32_t>, uint32_t> phiVersions;
    const size_t iterationLimit = std::max<size_t>(8, blocks_.size() * 4);
    for (size_t iteration = 0; iteration < iterationLimit; ++iteration) {
        bool changed = false;
        for (MidBlock& block : blocks_) {
            std::map<uint32_t, uint32_t> state;
            for (const auto& partition : memoryPartitions_)
                state[partition.first] = 0;
            if (!block.predecessors.empty()) {
                for (const auto& partition : memoryPartitions_) {
                    const uint32_t id = partition.first;
                    bool first = true;
                    uint32_t incoming = 0;
                    bool differs = false;
                    for (uint64_t predecessor : block.predecessors) {
                        const uint32_t version = outgoing[predecessor][id];
                        if (first) {
                            incoming = version;
                            first = false;
                        } else {
                            differs |= incoming != version;
                        }
                    }
                    if (differs) {
                        const auto key = std::make_pair(block.start, id);
                        auto inserted = phiVersions.emplace(key, nextVersion);
                        if (inserted.second) ++nextVersion;
                        incoming = inserted.first->second;
                        block.memoryPhis[id] = incoming;
                    }
                    state[id] = incoming;
                }
            }
            for (MidInstruction& operation : block.ops) {
                if (operation.op == POp::LOAD) {
                    operation.memoryVersionIn = state[operation.memoryPartition];
                } else if (operation.op == POp::STORE) {
                    operation.memoryVersionIn = state[operation.memoryPartition];
                    if (operation.memoryPartition == 0) {
                        for (auto& version : state)
                            version.second = operation.memoryVersionOut;
                    } else {
                        state[operation.memoryPartition] = operation.memoryVersionOut;
                    }
                } else if (operation.op == POp::CALL ||
                           operation.op == POp::CALLIND ||
                           operation.op == POp::SYSCALL) {
                    operation.memoryPartition = 0;
                    operation.memoryVersionIn = state[0];
                    for (auto& version : state)
                        version.second = operation.memoryVersionOut;
                }
            }
            if (outgoing[block.start] != state) {
                outgoing[block.start] = std::move(state);
                changed = true;
            }
        }
        if (!changed) break;
    }
}

MemoryLocation AliasAnalysis::resolve(MidValueId pointer,
                                      std::set<MidValueId>& visiting) const {
    MemoryLocation unknown;
    if (!pointer) return unknown;
    const auto cached = resolvedLocations_.find(pointer);
    if (cached != resolvedLocations_.end()) return cached->second;
    if (!visiting.insert(pointer).second) {
        resolvedLocations_[pointer] = unknown;
        return unknown;
    }
    auto remember = [&](MemoryLocation location) {
        resolvedLocations_[pointer] = location;
        return location;
    };
    const MidValue* value = ir_.value(pointer);
    if (!value) return remember(unknown);

    if (value->constant) {
        MemoryLocation location;
        location.kind = MemoryObjectKind::GLOBAL;
        location.byteOffset = static_cast<int64_t>(*value->constant);
        for (const auto& objectEntry : ir_.memoryObjects()) {
            const MemoryObject& object = objectEntry.second;
            if (object.kind != MemoryObjectKind::GLOBAL ||
                *value->constant < object.address)
                continue;
            const uint64_t relative = *value->constant - object.address;
            if (object.size && relative >= object.size) continue;
            location.object = object.id;
            location.byteOffset = static_cast<int64_t>(relative);
            break;
        }
        location.precise = true;
        return remember(location);
    }

    for (const auto& objectEntry : ir_.memoryObjects()) {
        const MemoryObject& object = objectEntry.second;
        if (object.kind == MemoryObjectKind::HEAP && object.value == pointer) {
            MemoryLocation location;
            location.kind = MemoryObjectKind::HEAP;
            location.object = object.id;
            location.precise = true;
            return remember(location);
        }
    }

    const auto definitionEntry = definitions_.find(pointer);
    const MidInstruction* definition = definitionEntry == definitions_.end()
                                           ? nullptr : definitionEntry->second;
    if (definition) {
        if (definition->phi && !definition->inputs.empty()) {
            MemoryLocation merged;
            bool first = true;
            for (MidValueId input : definition->inputs) {
                std::set<MidValueId> nested = visiting;
                const MemoryLocation incoming = resolve(input, nested);
                if (!incoming.precise) return remember(unknown);
                if (first) {
                    merged = incoming;
                    first = false;
                } else if (merged.kind != incoming.kind ||
                           merged.object != incoming.object ||
                           merged.byteOffset != incoming.byteOffset) {
                    return remember(unknown);
                }
            }
            return remember(merged);
        }
        if (definition->op == POp::COPY && !definition->inputs.empty())
            return remember(resolve(definition->inputs[0], visiting));
        if ((definition->op == POp::INT_ADD ||
             definition->op == POp::INT_SUB) &&
            definition->inputs.size() >= 2) {
            for (size_t side = 0; side < 2; ++side) {
                const MidValueId baseId = definition->inputs[side];
                const MidValue* displacement =
                    ir_.value(definition->inputs[1 - side]);
                if (!displacement || !displacement->constant) continue;
                std::set<MidValueId> nested = visiting;
                MemoryLocation base = resolve(baseId, nested);
                if (!base.precise) continue;
                int64_t delta = static_cast<int64_t>(*displacement->constant);
                if (definition->op == POp::INT_SUB && side == 0)
                    delta = -delta;
                else if (definition->op == POp::INT_SUB)
                    continue;
                base.byteOffset += delta;
                return remember(base);
            }
        }
    }

    if (value->storage == MidValue::REGISTER &&
        isStackRegister(ir_.architecture(), value->offset)) {
        MemoryLocation location;
        location.kind = MemoryObjectKind::STACK;
        location.object = value->offset;
        location.precise = true;
        return remember(location);
    }
    if (value->storage == MidValue::REGISTER &&
        (value->type.kind == TypeKind::POINTER ||
         value->type.kind == TypeKind::ARRAY ||
         value->type.kind == TypeKind::STRUCT ||
         value->type.kind == TypeKind::UNION)) {
        MemoryLocation location;
        location.kind = MemoryObjectKind::PARAMETER;
        location.object = pointer;
        location.precise = true;
        return remember(location);
    }
    return remember(unknown);
}

AliasAnalysis::AliasAnalysis(const MidIR& ir) : ir_(ir) {
    for (const MidBlock& block : ir.blocks()) {
        for (const MidInstruction& phi : block.phis)
            if (!phi.removed && phi.output) definitions_[phi.output] = &phi;
        for (const MidInstruction& operation : block.ops)
            if (!operation.removed && operation.output)
                definitions_[operation.output] = &operation;
    }
}

MemoryLocation AliasAnalysis::location(MidValueId pointer,
                                       uint64_t byteSize) const {
    std::set<MidValueId> visiting;
    MemoryLocation result = resolve(pointer, visiting);
    result.byteSize = byteSize;
    if (result.precise && result.object) {
        const MidValue* base = ir_.value(result.object);
        const DataType* aggregate = nullptr;
        if (base && base->type.kind == TypeKind::POINTER && base->type.detail &&
            base->type.detail->elementType)
            aggregate = base->type.detail->elementType.get();
        if (aggregate && aggregate->detail) {
            if (aggregate->kind == TypeKind::ARRAY &&
                aggregate->detail->elementType) {
                const uint64_t elementSize = static_cast<uint64_t>(
                    std::max(1, aggregate->detail->elementType->bits / 8));
                if (result.byteOffset >= 0 && elementSize)
                    result.fieldPath = "[" + std::to_string(
                        static_cast<uint64_t>(result.byteOffset) / elementSize) + "]";
            } else {
                for (const TypeField& field : aggregate->detail->fields) {
                    const uint64_t fieldSize = static_cast<uint64_t>(
                        std::max(1, field.type.bits / 8));
                    if (result.byteOffset >= 0 &&
                        static_cast<uint64_t>(result.byteOffset) >= field.byteOffset &&
                        static_cast<uint64_t>(result.byteOffset) <
                            field.byteOffset + fieldSize) {
                        result.fieldPath = field.name;
                        break;
                    }
                }
            }
        }
    }
    return result;
}

AliasResult AliasAnalysis::alias(MidValueId left, uint64_t leftSize,
                                 MidValueId right, uint64_t rightSize) const {
    if (left == right)
        return leftSize == rightSize ? AliasResult::MUST_ALIAS
                                     : AliasResult::PARTIAL_ALIAS;
    const MemoryLocation a = location(left, leftSize);
    const MemoryLocation b = location(right, rightSize);
    if (!a.precise || !b.precise) return AliasResult::MAY_ALIAS;
    if (a.kind != b.kind) {
        if ((a.kind == MemoryObjectKind::STACK && b.kind == MemoryObjectKind::GLOBAL) ||
            (a.kind == MemoryObjectKind::GLOBAL && b.kind == MemoryObjectKind::STACK) ||
            (a.kind == MemoryObjectKind::HEAP && b.kind == MemoryObjectKind::GLOBAL) ||
            (a.kind == MemoryObjectKind::GLOBAL && b.kind == MemoryObjectKind::HEAP))
            return AliasResult::NO_ALIAS;
        return AliasResult::MAY_ALIAS;
    }
    if (a.kind == MemoryObjectKind::PARAMETER && a.object != b.object)
        return AliasResult::MAY_ALIAS;
    if (a.kind == MemoryObjectKind::STACK && a.object != b.object)
        return AliasResult::MAY_ALIAS;
    if (a.byteOffset == b.byteOffset && leftSize == rightSize)
        return AliasResult::MUST_ALIAS;
    if (!leftSize || !rightSize) return AliasResult::MAY_ALIAS;
    const long double aBegin = static_cast<long double>(a.byteOffset);
    const long double bBegin = static_cast<long double>(b.byteOffset);
    const long double aEnd = aBegin + static_cast<long double>(leftSize);
    const long double bEnd = bBegin + static_cast<long double>(rightSize);
    if (aEnd <= bBegin || bEnd <= aBegin) return AliasResult::NO_ALIAS;
    return AliasResult::PARTIAL_ALIAS;
}

bool AliasAnalysis::mayClobber(const MidInstruction& write,
                               const MidInstruction& read) const {
    if (write.op != POp::STORE || write.inputs.empty() ||
        (read.op != POp::LOAD && read.op != POp::STORE) || read.inputs.empty())
        return true;
    return alias(write.inputs[0], accessSize(ir_, write),
                 read.inputs[0], accessSize(ir_, read)) != AliasResult::NO_ALIAS;
}

} // namespace centrifuge
