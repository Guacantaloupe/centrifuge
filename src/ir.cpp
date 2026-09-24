// centrifuge - function-level SSA, type, ABI, optimization, and jump tables
#include "centrifuge/ir.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <thread>
#include <tuple>

#include "centrifuge/decompile.hpp"
#include "centrifuge/calling_convention.hpp"
#include "centrifuge/import_prototype.hpp"

namespace centrifuge {

using RegKey = std::pair<uint64_t, int>;

int inputCount(POp op) {
    switch (op) {
    case POp::COPY: case POp::LOAD: case POp::BRANCH: case POp::BRANCHIND:
    case POp::CALL: case POp::CALLIND: case POp::INT_ZEXT: case POp::INT_SEXT:
    case POp::INT_NEGATE: case POp::BOOL_NEGATE: case POp::INT_PARITY:
    case POp::INT_POPCOUNT: case POp::INT_COUNT_LEADING_ZERO:
    case POp::INT_COUNT_TRAILING_ZERO:
    case POp::FLOAT_NEG: case POp::FLOAT_ABS: case POp::FLOAT_SQRT:
    case POp::FLOAT_FLOAT2INT:
        return 1;
    case POp::STORE: case POp::SELECT: case POp::SIMD_MASK: return 3;
    case POp::RETURN: case POp::TRAP: case POp::SYSCALL: return 0;
    default: return 2;
    }
}

bool pure(POp op) {
    return op != POp::STORE && op != POp::BRANCH && op != POp::CBRANCH &&
           op != POp::BRANCHIND && op != POp::CALL && op != POp::CALLIND &&
           op != POp::RETURN && op != POp::TRAP && op != POp::SYSCALL &&
           op != POp::LOAD;
}

uint64_t maskFor(int size) {
    return size <= 0 || size >= 8 ? ~0ULL : ((1ULL << (size * 8)) - 1);
}

std::optional<uint64_t> fold(POp op, uint64_t a, uint64_t b, int size) {
    const uint64_t mask = maskFor(size);
    switch (op) {
    case POp::INT_ADD: return (a + b) & mask;
    case POp::INT_SUB: return (a - b) & mask;
    case POp::INT_MULT: return (a * b) & mask;
    case POp::INT_AND: return (a & b) & mask;
    case POp::INT_OR: return (a | b) & mask;
    case POp::INT_XOR: return (a ^ b) & mask;
    case POp::INT_LEFT: return b < 64 ? (a << b) & mask : 0;
    case POp::INT_RIGHT: return b < 64 ? (a & mask) >> b : 0;
    case POp::INT_EQUAL: return (a & mask) == (b & mask);
    case POp::INT_NOTEQUAL: return (a & mask) != (b & mask);
    case POp::INT_LESS: return (a & mask) < (b & mask);
    case POp::INT_LESSEQUAL: return (a & mask) <= (b & mask);
    case POp::BOOL_AND: return (a != 0) && (b != 0);
    case POp::BOOL_OR: return (a != 0) || (b != 0);
    case POp::BOOL_XOR: return (a != 0) != (b != 0);
    default: return std::nullopt;
    }
}

DataType mergeType(DataType a, DataType b) {
    if (a.kind == TypeKind::UNKNOWN) return b;
    if (b.kind == TypeKind::UNKNOWN) return a;
    if (a == b) return a;
    if (a.kind == TypeKind::FUNCTION_POINTER || b.kind == TypeKind::FUNCTION_POINTER)
        return a.kind == TypeKind::FUNCTION_POINTER ? a : b;
    if (a.kind == TypeKind::POINTER || b.kind == TypeKind::POINTER) {
        DataType result{TypeKind::POINTER, std::max(a.bits, b.bits), 1};
        result.detail = a.kind == TypeKind::POINTER && a.detail ? a.detail : b.detail;
        return result;
    }
    if (a.kind == TypeKind::VECTOR || b.kind == TypeKind::VECTOR)
        return {TypeKind::VECTOR, std::max(a.bits, b.bits),
                std::max(a.lanes, b.lanes)};
    if (a.kind == TypeKind::FLOAT || b.kind == TypeKind::FLOAT)
        return {TypeKind::FLOAT, std::max(a.bits, b.bits), 1};
    if (a.kind == TypeKind::BOOL && b.kind == TypeKind::BOOL) return a;
    const bool signedValue = a.kind == TypeKind::SIGNED_INT ||
                             b.kind == TypeKind::SIGNED_INT;
    return {signedValue ? TypeKind::SIGNED_INT : TypeKind::UNSIGNED_INT,
            std::max(a.bits, b.bits), 1};
}

std::vector<std::pair<uint64_t, std::string>> abiArguments(
    const std::string& architecture, const std::string& callingConvention) {
    std::vector<std::pair<uint64_t, std::string>> arguments;
    if (architecture.rfind("x86", 0) == 0) {
        if (callingConvention == "win64" || callingConvention == "ms")
            return {{1 * 8, "arg0"}, {2 * 8, "arg1"},
                    {8 * 8, "arg2"}, {9 * 8, "arg3"}};
        return {{7 * 8, "arg0"}, {6 * 8, "arg1"}, {2 * 8, "arg2"},
                {1 * 8, "arg3"}, {8 * 8, "arg4"}, {9 * 8, "arg5"}};
    }
    if (architecture.rfind("riscv", 0) == 0) {
        for (int index = 0; index < 8; ++index)
            arguments.emplace_back((10 + index) * 8,
                                   "arg" + std::to_string(index));
        return arguments;
    }
    if (architecture == "aarch64" || architecture == "arm64") {
        for (int index = 0; index < 8; ++index)
            arguments.emplace_back(index * 8, "arg" + std::to_string(index));
        return arguments;
    }
    return {{0, "arg0"}, {8, "arg1"}, {16, "arg2"}, {24, "arg3"}};
}


std::string DataType::name() const {
    switch (kind) {
    case TypeKind::BOOL: return "bool";
    case TypeKind::POINTER: return "void *";
    case TypeKind::FLOAT: return bits <= 32 ? "float" : "double";
    case TypeKind::VECTOR:
        return "vector" + std::to_string(bits) + "x" + std::to_string(lanes);
    case TypeKind::ARRAY:
        return detail && detail->elementType ? detail->elementType->name() + " *"
                                             : "void *";
    case TypeKind::STRUCT:
        return "struct " + (detail && !detail->name.empty() ? detail->name
                                                              : "anonymous");
    case TypeKind::UNION:
        return "union " + (detail && !detail->name.empty() ? detail->name
                                                              : "anonymous");
    case TypeKind::FUNCTION_POINTER:
        return "void (*)(void)";
    case TypeKind::SIGNED_INT: return "int" + std::to_string(bits) + "_t";
    case TypeKind::UNSIGNED_INT: return "uint" + std::to_string(bits) + "_t";
    case TypeKind::MEMORY: return "memory";
    case TypeKind::VOID_TYPE: return "void";
    case TypeKind::UNKNOWN: return bits ? "uint" + std::to_string(bits) + "_t"
                                         : "uint64_t";
    }
    return "uint64_t";
}

std::string DataType::declaration(const std::string& identifier) const {
    if (kind == TypeKind::ARRAY && detail && detail->elementType)
        return detail->elementType->name() + " " + identifier + "[" +
               std::to_string(detail->elementCount) + "]";
    if (kind == TypeKind::FUNCTION_POINTER && detail) {
        const std::string result = detail->returnType
                                       ? detail->returnType->name() : "void";
        std::string out = result + " (*" + identifier + ")(";
        for (size_t i = 0; i < detail->parameterTypes.size(); ++i) {
            if (i) out += ", ";
            out += detail->parameterTypes[i].name();
        }
        if (detail->variadic)
            out += detail->parameterTypes.empty() ? "..." : ", ...";
        else if (detail->parameterTypes.empty()) out += "void";
        return out + ")";
    }
    if (kind == TypeKind::POINTER && detail && detail->elementType)
        return detail->elementType->kind == TypeKind::ARRAY &&
                       detail->elementType->detail &&
                       detail->elementType->detail->elementType
                   ? detail->elementType->detail->elementType->name() + " *" +
                         identifier
                   : detail->elementType->name() + " *" + identifier;
    return name() + " " + identifier;
}

std::string FunctionSignature::declaration(const std::string& name) const {
    std::string out = returnType.name() + " " + name + "(";
    if (parameters.empty() && !variadic) out += "void";
    for (size_t i = 0; i < parameters.size(); ++i) {
        if (i) out += ", ";
        out += parameters[i].type.declaration(parameters[i].name);
    }
    if (variadic) out += parameters.empty() ? "..." : ", ...";
    return out + ")";
}

bool FunctionIR::build(const CfgBuilder& cfg, const std::string& architecture,
                       const std::string& callingConvention) {
    arch_ = architecture;
    callingConvention_ = callingConvention;
    blocks_.clear(); blockIndex_.clear(); values_.clear(); outgoing_.clear();
    parameters_.clear(); stackInputs_.clear(); nextId_ = 1;
    hasTailCall_ = false;
    memoryObjects_.clear(); memoryPartitions_.clear(); nextMemoryObject_ = 1;
    if (cfg.blocks().empty()) return false;

    std::set<RegKey> registers;
    bool containsCall = false;
    for (const auto& block : cfg.blocks()) {
        containsCall |= block.isTailCall();
        hasTailCall_ |= block.isTailCall();
        // An indirect tail call (data-slot jump board: `mov reg,[slot];
        // jmp *reg`) has no statically known target, so cfg.tailCallTarget
        // is unset.  Recognize a block ending in an unresolved indirect
        // branch whose target register is written earlier in the same
        // block: the jump forwards the callee's return value, so the
        // function must not infer as void (the recovered dispatch case
        // would then return 0 and allocator boards would hand callers
        // NULL).
        const PcodeInsn* terminator = block.terminator();
        if (terminator &&
            (terminator->kind == Insn::JMP ||
             terminator->kind == Insn::OTHER) &&
            !terminator->targetKnown) {
            for (const PcodeOp& operation : terminator->ops) {
                if (operation.op != POp::BRANCHIND &&
                    operation.op != POp::BRANCH)
                    continue;
                const Varnode* target = terminator->find(operation.in0);
                if (!target) continue;
                uint64_t targetOffset = 0;
                bool registerTarget = false;
                if (target->kind == Varnode::REGISTER) {
                    targetOffset = target->offset;
                    registerTarget = true;
                } else if (target->kind == Varnode::UNIQUE) {
                    // Trace a temp back to its defining op.  A COPY
                    // carries a register (`mov reg,[slot]; jmp *reg`); an
                    // INT_ADD/INT_SUB of a register and a constant is a
                    // memory-indirect jump (`jmp qword ptr [reg+K]`).
                    for (const PcodeOp& defining : terminator->ops) {
                        if (defining.out != target->id) continue;
                        if (defining.op == POp::COPY) {
                            const Varnode* source =
                                terminator->find(defining.in0);
                            if (source &&
                                source->kind == Varnode::REGISTER) {
                                targetOffset = source->offset;
                                registerTarget = true;
                            }
                        } else if (defining.op == POp::INT_ADD ||
                                   defining.op == POp::INT_SUB) {
                            for (const uint64_t input :
                                 {defining.in0, defining.in1}) {
                                const Varnode* operand =
                                    terminator->find(input);
                                if (operand &&
                                    operand->kind == Varnode::REGISTER) {
                                    targetOffset = operand->offset;
                                    registerTarget = true;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                    if (!registerTarget) continue;
                } else {
                    continue;
                }
                bool writtenHere = false;
                for (const auto& insn : block.insns)
                    for (const PcodeOp& inner : insn.ops) {
                        const Varnode* out = insn.find(inner.out);
                        if (out && out->kind == Varnode::REGISTER &&
                            out->offset == targetOffset) {
                            writtenHere = true;
                            break;
                        }
                    }
                if (writtenHere) {
                    hasTailCall_ = true;
                    break;
                }
            }
        }
        for (const auto& insn : block.insns)
            for (const PcodeOp& operation : insn.ops) {
                containsCall |= operation.op == POp::CALL ||
                                operation.op == POp::CALLIND;
                const Varnode* nodes[] = {insn.find(operation.in0),
                                          insn.find(operation.in1),
                                          insn.find(operation.in2),
                                          insn.find(operation.out)};
                for (const Varnode* node : nodes)
                    if (node && node->kind == Varnode::REGISTER)
                        registers.emplace(node->offset, node->size);
            }
    }

    // A machine CALL consumes the current ABI argument registers even when
    // the instruction encoding only names its target.  Materialize those
    // live-ins so forwarding thunks do not silently replace RCX/RDX/R8/R9
    // (or the equivalent registers on other targets) with zero.
    if (containsCall) {
        const int registerBytes = architecture == "x86" ? 4 : 8;
        for (const auto& argument : abiArguments(architecture,
                                                 callingConvention_))
            registers.emplace(argument.first, registerBytes);
    }

    auto makeValue = [&](SsaValue value) {
        value.id = nextId_++;
        const SsaId id = value.id;
        values_.emplace(id, std::move(value));
        return id;
    };
    for (const RegKey& key : registers) {
        SsaValue v;
        v.storage = SsaValue::REGISTER; v.offset = key.first; v.size = key.second;
        v.version = 0; v.name = "r" + std::to_string(key.first) + "_0";
        v.type.bits = key.second * 8;
        parameters_[key] = makeValue(std::move(v));
    }
    const RegKey memoryKey{std::numeric_limits<uint64_t>::max(), 0};
    SsaValue memory;
    memory.storage = SsaValue::MEMORY_STATE; memory.name = "mem_0";
    memory.type = {TypeKind::MEMORY, 0, 1};
    parameters_[memoryKey] = makeValue(std::move(memory));

    std::map<RegKey, uint32_t> versions;
    for (const RegKey& key : registers) versions[key] = 0;
    versions[memoryKey] = 0;

    // Allocate blocks and deliberately non-pruned phi nodes at every join.
    // This is conservative SSA and remains correct for irreducible graphs.
    for (const auto& block : cfg.blocks()) {
        SsaBlock sb;
        sb.start = block.start;
        sb.successors = block.succs;
        sb.successors.insert(sb.successors.end(), block.exceptionSuccs.begin(),
                             block.exceptionSuccs.end());
        std::sort(sb.successors.begin(), sb.successors.end());
        sb.successors.erase(std::unique(sb.successors.begin(), sb.successors.end()),
                            sb.successors.end());
        const auto preds = cfg.predecessors(block.start);
        sb.predecessors.assign(preds.begin(), preds.end());
        blocks_.push_back(std::move(sb));
    }
    for (size_t i = 0; i < blocks_.size(); ++i) blockIndex_[blocks_[i].start] = i;

    std::map<uint64_t, std::map<RegKey, SsaId>> phiValues;
    for (SsaBlock& block : blocks_) {
        if (block.predecessors.size() < 2) continue;
        for (const auto& parameter : parameters_) {
            const RegKey key = parameter.first;
            SsaValue v = values_.at(parameter.second);
            v.version = ++versions[key];
            v.name = key == memoryKey ? "mem_" + std::to_string(v.version)
                                      : "r" + std::to_string(key.first) + "_" +
                                            std::to_string(v.version);
            const SsaId id = makeValue(std::move(v));
            phiValues[block.start][key] = id;
            block.phis.push_back(SsaOp{POp::COPY, id, {}, block.start, true, false});
        }
    }

    struct DefSite { SsaId id = 0; RegKey key{}; };
    std::map<std::tuple<uint64_t, uint64_t, size_t>, DefSite> definitions;
    for (const auto& block : cfg.blocks()) {
        for (const auto& insn : block.insns) {
            for (size_t oi = 0; oi < insn.ops.size(); ++oi) {
                const PcodeOp& op = insn.ops[oi];
                const Varnode* outNode = insn.find(op.out);
                RegKey key = memoryKey;
                SsaValue v;
                if (op.op == POp::CALL || op.op == POp::CALLIND) {
                    key = {std::numeric_limits<uint64_t>::max() - 1,
                           static_cast<int>(nextId_ & 0x7fffffff)};
                    v.storage = SsaValue::TEMPORARY;
                    v.size = architecture.rfind("x86", 0) == 0 &&
                                     architecture == "x86" ? 4 : 8;
                    v.type = {TypeKind::UNKNOWN, v.size * 8, 1};
                } else if (op.op == POp::STORE) {
                    v.storage = SsaValue::MEMORY_STATE; v.type = {TypeKind::MEMORY, 0, 1};
                } else if (!outNode) {
                    continue;
                } else if (outNode->kind == Varnode::REGISTER) {
                    key = {outNode->offset, outNode->size};
                    v.storage = SsaValue::REGISTER; v.offset = key.first; v.size = key.second;
                    v.type.bits = key.second * 8;
                } else {
                    key = {std::numeric_limits<uint64_t>::max() - 1,
                           static_cast<int>(nextId_ & 0x7fffffff)};
                    v.storage = SsaValue::TEMPORARY; v.size = outNode->size;
                    v.type.bits = outNode->size * 8;
                }
                v.version = ++versions[key];
                v.name = v.storage == SsaValue::REGISTER
                             ? "r" + std::to_string(v.offset) + "_" + std::to_string(v.version)
                         : v.storage == SsaValue::MEMORY_STATE
                             ? "mem_" + std::to_string(v.version)
                             : "t" + std::to_string(nextId_);
                definitions[{block.start, insn.addr, oi}] = {makeValue(std::move(v)), key};
            }
        }
    }

    // Outgoing register versions are determined solely by fixed definition
    // sites, so loops do not require speculative renaming passes.
    for (const auto& block : cfg.blocks()) {
        std::map<RegKey, SsaId> state = parameters_;
        const auto blockPreds = cfg.predecessors(block.start);
        if (blockPreds.size() == 1) {
            const uint64_t pred = *blockPreds.begin();
            if (outgoing_.count(pred)) state = outgoing_[pred];
        }
        if (phiValues.count(block.start))
            for (const auto& p : phiValues[block.start]) state[p.first] = p.second;
        for (const auto& insn : block.insns)
            for (size_t oi = 0; oi < insn.ops.size(); ++oi) {
                const auto it = definitions.find({block.start, insn.addr, oi});
                if (it != definitions.end() &&
                    (it->second.key == memoryKey ||
                     values_.at(it->second.id).storage == SsaValue::REGISTER))
                    state[it->second.key] = it->second.id;
            }
        outgoing_[block.start] = std::move(state);
    }

    // Repair single-predecessor states now that loop back-edge outputs exist.
    for (const auto& block : cfg.blocks()) {
        const auto preds = cfg.predecessors(block.start);
        if (preds.size() != 1) continue;
        std::map<RegKey, SsaId> state = outgoing_.at(*preds.begin());
        for (const auto& insn : block.insns)
            for (size_t oi = 0; oi < insn.ops.size(); ++oi) {
                const auto it = definitions.find({block.start, insn.addr, oi});
                if (it != definitions.end() &&
                    (it->second.key == memoryKey ||
                     values_.at(it->second.id).storage == SsaValue::REGISTER))
                    state[it->second.key] = it->second.id;
            }
        outgoing_[block.start] = std::move(state);
    }

    // Populate phi inputs from predecessor exit states.
    for (SsaBlock& block : blocks_) {
        if (!phiValues.count(block.start)) continue;
        size_t pi = 0;
        for (const auto& p : phiValues[block.start]) {
            for (uint64_t pred : block.predecessors) {
                const auto state = outgoing_.find(pred);
                if (state == outgoing_.end()) {
                    block.phis[pi].inputs.push_back(parameters_.at(p.first));
                } else {
                    const auto val = state->second.find(p.first);
                    block.phis[pi].inputs.push_back(
                        val != state->second.end() ? val->second
                                                   : parameters_.at(p.first));
                }
            }
            ++pi;
        }
    }

    // Recover the architectural stack-pointer value at each instruction,
    // relative to the function-entry SP.  Stack operands in p-code are
    // expressed relative to the *current* SP; treating every SP reference as
    // entry-relative misclassifies saved nonvolatile registers as arguments
    // and moves real Win64 stack arguments by the size of the prologue.
    const uint64_t functionSpOffset = arch_.rfind("x86", 0) == 0 ? 4 * 8
                                      : arch_.rfind("riscv", 0) == 0 ? 2 * 8
                                      : (arch_ == "aarch64" || arch_ == "arm64")
                                            ? 31 * 8 : 0;
    auto relativeToInstructionSp = [&](const PcodeInsn& insn, uint64_t id) {
        std::function<std::optional<int64_t>(uint64_t, std::set<uint64_t>&)>
            resolve;
        resolve = [&](uint64_t valueId, std::set<uint64_t>& visiting)
            -> std::optional<int64_t> {
            if (!visiting.insert(valueId).second) return std::nullopt;
            const Varnode* node = insn.find(valueId);
            if (!node) return std::nullopt;
            if (node->kind == Varnode::REGISTER &&
                node->offset == functionSpOffset)
                return 0;
            if (node->kind != Varnode::UNIQUE) return std::nullopt;
            for (const PcodeOp& definition : insn.ops) {
                if (definition.out != valueId) continue;
                if (definition.op == POp::COPY)
                    return resolve(definition.in0, visiting);
                if (definition.op != POp::INT_ADD &&
                    definition.op != POp::INT_SUB)
                    continue;
                for (int side = 0; side < 2; ++side) {
                    std::set<uint64_t> nested = visiting;
                    const auto base = resolve(
                        side ? definition.in1 : definition.in0, nested);
                    const Varnode* displacement = insn.find(
                        side ? definition.in0 : definition.in1);
                    if (!base || !displacement || !displacement->isConst())
                        continue;
                    int64_t delta = static_cast<int64_t>(displacement->offset);
                    if (definition.op == POp::INT_SUB && side == 0)
                        delta = -delta;
                    else if (definition.op == POp::INT_SUB)
                        continue;
                    return *base + delta;
                }
            }
            return std::nullopt;
        };
        std::set<uint64_t> visiting;
        return resolve(id, visiting);
    };
    auto stackAdjustment = [&](const PcodeInsn& insn)
        -> std::optional<int64_t> {
        std::optional<int64_t> result;
        for (const PcodeOp& op : insn.ops) {
            const Varnode* output = insn.find(op.out);
            if (!output || output->kind != Varnode::REGISTER ||
                output->offset != functionSpOffset)
                continue;
            if (op.op == POp::COPY) {
                result = relativeToInstructionSp(insn, op.in0);
                continue;
            }
            if (op.op != POp::INT_ADD && op.op != POp::INT_SUB) continue;
            for (int side = 0; side < 2; ++side) {
                const auto base = relativeToInstructionSp(
                    insn, side ? op.in1 : op.in0);
                const Varnode* displacement = insn.find(
                    side ? op.in0 : op.in1);
                if (!base || !displacement || !displacement->isConst())
                    continue;
                int64_t delta = static_cast<int64_t>(displacement->offset);
                if (op.op == POp::INT_SUB && side == 0)
                    delta = -delta;
                else if (op.op == POp::INT_SUB)
                    continue;
                result = *base + delta;
                break;
            }
        }
        return result;
    };
    std::map<uint64_t, int64_t> blockEntryStackBias;
    std::map<uint64_t, int64_t> instructionStackBias;
    if (!cfg.blocks().empty()) {
        std::deque<uint64_t> pendingBlocks{cfg.blocks().front().start};
        blockEntryStackBias[cfg.blocks().front().start] = 0;
        while (!pendingBlocks.empty()) {
            const uint64_t address = pendingBlocks.front();
            pendingBlocks.pop_front();
            const CfgBlock* block = cfg.blockAt(address);
            if (!block) continue;
            int64_t bias = blockEntryStackBias[address];
            for (const PcodeInsn& insn : block->insns) {
                instructionStackBias.emplace(insn.addr, bias);
                if (const auto adjustment = stackAdjustment(insn))
                    bias += *adjustment;
            }
            for (uint64_t successor : block->succs) {
                const auto inserted = blockEntryStackBias.emplace(successor, bias);
                if (inserted.second) pendingBlocks.push_back(successor);
                // A balanced ABI frame has the same SP at every join.  On a
                // conflict retain the first proven path instead of iterating
                // an alloca-style loop indefinitely.
            }
        }
    }

    // Rename p-code uses in block order.
    for (const auto& block : cfg.blocks()) {
        SsaBlock& sb = blocks_[blockIndex_.at(block.start)];
        std::map<RegKey, SsaId> state = parameters_;
        const auto preds = cfg.predecessors(block.start);
        if (preds.size() == 1) state = outgoing_.at(*preds.begin());
        if (phiValues.count(block.start))
            for (const auto& p : phiValues[block.start]) state[p.first] = p.second;

        for (const auto& insn : block.insns) {
            std::map<uint64_t, SsaId> local;
            const uint64_t spOffset = functionSpOffset;
            const auto knownBias = instructionStackBias.find(insn.addr);
            const int64_t instructionBias = knownBias == instructionStackBias.end()
                                                ? 0 : knownBias->second;
            std::function<std::optional<int64_t>(uint64_t, std::set<uint64_t>&)>
                stackOffsetOf;
            stackOffsetOf = [&](uint64_t id, std::set<uint64_t>& visiting)
                -> std::optional<int64_t> {
                if (!visiting.insert(id).second) return std::nullopt;
                const Varnode* node = insn.find(id);
                if (!node) return std::nullopt;
                if (node->kind == Varnode::REGISTER &&
                    node->offset == spOffset)
                    return instructionBias;
                if (node->kind != Varnode::UNIQUE) return std::nullopt;
                for (const PcodeOp& definition : insn.ops) {
                    if (definition.out != id) continue;
                    if (definition.op == POp::COPY)
                        return stackOffsetOf(definition.in0, visiting);
                    if (definition.op != POp::INT_ADD &&
                        definition.op != POp::INT_SUB)
                        continue;
                    for (int side = 0; side < 2; ++side) {
                        std::set<uint64_t> nested = visiting;
                        const auto base = stackOffsetOf(
                            side ? definition.in1 : definition.in0, nested);
                        const Varnode* displacement = insn.find(
                            side ? definition.in0 : definition.in1);
                        if (!base || !displacement || !displacement->isConst())
                            continue;
                        int64_t delta = static_cast<int64_t>(displacement->offset);
                        if (definition.op == POp::INT_SUB && side == 0)
                            delta = -delta;
                        else if (definition.op == POp::INT_SUB)
                            continue;
                        return *base + delta;
                    }
                }
                return std::nullopt;
            };
            auto use = [&](uint64_t varnodeId) -> SsaId {
                if (!varnodeId) return 0;
                if (local.count(varnodeId)) return local[varnodeId];
                const Varnode* node = insn.find(varnodeId);
                if (!node) return 0;
                if (node->kind == Varnode::REGISTER) {
                    const RegKey key{node->offset, node->size};
                    return state.count(key) ? state[key] : parameters_.at(key);
                }
                if (node->kind == Varnode::CONST) {
                    SsaValue c;
                    c.storage = SsaValue::CONSTANT; c.size = node->size;
                    c.type = {TypeKind::UNSIGNED_INT, node->size * 8, 1};
                    c.constant = node->offset; c.name = std::to_string(node->offset);
                    const SsaId id = makeValue(std::move(c)); local[varnodeId] = id;
                    return id;
                }
                return local.count(varnodeId) ? local[varnodeId] : 0;
            };
            for (size_t oi = 0; oi < insn.ops.size(); ++oi) {
                const PcodeOp& op = insn.ops[oi];
                SsaOp so; so.op = op.op; so.address = insn.addr;
                const int count = inputCount(op.op);
                if (count >= 1) so.inputs.push_back(use(op.in0));
                if (count >= 2) so.inputs.push_back(use(op.in1));
                if (count >= 3) so.inputs.push_back(use(op.in2));
                if (op.op == POp::LOAD) so.inputs.push_back(state[memoryKey]);
                if (op.op == POp::CALL || op.op == POp::CALLIND) {
                    const int registerBytes = arch_ == "x86" ? 4 : 8;
                    for (const auto& argument : abiArguments(
                             arch_, callingConvention_)) {
                        const RegKey key{argument.first, registerBytes};
                        const auto current = state.find(key);
                        if (current != state.end())
                            so.inputs.push_back(current->second);
                    }
                }
                if (block.isTailCall() &&
                    (op.op == POp::BRANCH || op.op == POp::BRANCHIND)) {
                    const int registerBytes = arch_ == "x86" ? 4 : 8;
                    for (const auto& argument : abiArguments(
                             arch_, callingConvention_)) {
                        const RegKey key{argument.first, registerBytes};
                        const auto current = state.find(key);
                        if (current != state.end())
                            so.inputs.push_back(current->second);
                    }
                }
                const auto def = definitions.find({block.start, insn.addr, oi});
                if (def != definitions.end()) {
                    so.output = def->second.id;
                    const Varnode* node = insn.find(op.out);
                    if (node) local[op.out] = so.output;
                    if (def->second.key == memoryKey ||
                        values_.at(so.output).storage == SsaValue::REGISTER)
                        state[def->second.key] = so.output;
                }
                if ((op.op == POp::CALL || op.op == POp::CALLIND) &&
                    so.output) {
                    // Route the call result into the return register's
                    // state.  The CALL output is a temporary keyed by a
                    // synthetic RegKey, so without this every post-call
                    // read of the return register resolves to the stale
                    // pre-call value: downstream uses (spills, field
                    // dereferences, returns) become invisible to SSA
                    // consumers such as return-consumption evidence and
                    // call-result field attribution.
                    const uint64_t retOff =
                        arch_.rfind("riscv", 0) == 0 ? 10 * 8 : 0;
                    state[{retOff, 8}] = so.output;
                    state[{retOff, 4}] = so.output;
                }
                if (op.op == POp::LOAD && so.output) {
                    std::set<uint64_t> visiting;
                    const auto offset = stackOffsetOf(op.in0, visiting);
                    const int64_t firstArgument =
                        arch_.rfind("x86", 0) == 0
                            ? ((callingConvention_ == "win64" ||
                                callingConvention_ == "ms") ? 40 : 8)
                            : 0;
                    if (offset && *offset >= firstArgument)
                        stackInputs_.emplace(*offset, so.output);
                }
                sb.ops.push_back(std::move(so));
            }
        }
    }
    const bool reportProgress = std::getenv("CENTRIFUGE_ANALYSIS_PROGRESS") != nullptr;
    auto reportBuildStage = [&](const char* stage) {
        if (!reportProgress) return;
        std::fprintf(stderr, "[midir 0x%llx] %s\n",
                     static_cast<unsigned long long>(blocks_.front().start), stage);
        std::fflush(stderr);
    };
    reportBuildStage("renamed");
    inferTypes();
    reportBuildStage("types");
    partitionMemory();
    reportBuildStage("memory-ssa");
    const MidIRVerification verification = verify();
    reportBuildStage("verified");
    return verification.valid();
}

void FunctionIR::inferTypes() {
    auto constrain = [&](SsaId id, DataType wanted) {
        auto it = values_.find(id);
        if (it == values_.end()) return false;
        const DataType merged = mergeType(it->second.type, wanted);
        if (merged == it->second.type) return false;
        it->second.type = merged; return true;
    };
    // Phase 7: attach an element type to a pointer value's TypeDetail.
    // Conservative: never downgrade a known element; widen UNKNOWN only.
    auto attachElementType = [&](SsaId pointerId, const DataType& element,
                                  std::map<SsaId, SsaValue>& values) {
        auto it = values.find(pointerId);
        if (it == values.end() || element.bits == 0) return false;
        DataType& type = it->second.type;
        if (type.kind != TypeKind::POINTER)
            type = {TypeKind::POINTER, 64, 1};
        if (!type.detail) type.detail = std::make_shared<TypeDetail>();
        if (!type.detail->elementType) {
            type.detail->elementType =
                std::make_shared<DataType>(element);
            return true;
        }
        DataType& current = *type.detail->elementType;
        if (current.kind == TypeKind::UNKNOWN && current.bits == 0) {
            current = element;
            return true;
        }
        // Float evidence upgrades a width-inferred unsigned element.
        if (element.kind == TypeKind::FLOAT &&
            current.kind == TypeKind::UNSIGNED_INT &&
            current.bits == element.bits) {
            current = element;
            return true;
        }
        if (current.kind == element.kind &&
            (element.bits > current.bits || current.bits == 0)) {
            current.bits = element.bits;
            return true;
        }
        return false;
    };
    bool changed = true;
    for (int pass = 0; changed && pass < 32; ++pass) {
        changed = false;
        for (const SsaBlock& block : blocks_) {
            for (const SsaOp& phi : block.phis) {
                DataType merged;
                for (SsaId input : phi.inputs)
                    if (const SsaValue* v = value(input)) merged = mergeType(merged, v->type);
                changed |= constrain(phi.output, merged);
                // A phi represents one logical value on all incoming edges.
                // Propagate the joined type back to entry/live-in values so
                // pointer evidence discovered after a loop is not stranded
                // on the phi result.
                if (const SsaValue* output = value(phi.output))
                    for (SsaId input : phi.inputs)
                        changed |= constrain(input, output->type);
            }
            for (const SsaOp& op : block.ops) {
                const SsaValue* out = value(op.output);
                const int bits = out && out->size ? out->size * 8 : 64;
                switch (op.op) {
                case POp::COPY:
                    if (!op.inputs.empty()) {
                        const SsaValue* input = value(op.inputs[0]);
                        if (input) changed |= constrain(op.output, input->type);
                        if (const SsaValue* output = value(op.output))
                            changed |= constrain(op.inputs[0], output->type);
                    }
                    break;
                case POp::CALLIND:
                    if (!op.inputs.empty()) {
                        DataType functionPointer{TypeKind::FUNCTION_POINTER, 64, 1};
                        functionPointer.detail = std::make_shared<TypeDetail>();
                        functionPointer.detail->returnType = std::make_shared<DataType>(
                            DataType{TypeKind::UNKNOWN, 64, 1});
                        changed |= constrain(op.inputs[0], functionPointer);
                    }
                    break;
                case POp::CBRANCH:
                    if (op.inputs.size() > 1) changed |= constrain(op.inputs[1], {TypeKind::BOOL, 1, 1});
                    break;
                case POp::LOAD:
                    if (!op.inputs.empty()) {
                        changed |= constrain(op.inputs[0],
                                             {TypeKind::POINTER, 64, 1});
                        // Phase 7: recover the pointer's element type from
                        // the access width and the loaded value's kind.
                        // Scalar inference covers <=8-byte accesses; SSE
                        // scalar loads (movsd/movss) present a 16-byte xmm
                        // container whose logical element is 4/8 bytes.
                        const SsaValue* loaded = value(op.output);
                        if (loaded && loaded->size > 0 && loaded->size <= 16) {
                            const int elementBits =
                                loaded->size <= 8 ? loaded->size * 8 : 64;
                            DataType element{
                                loaded->type.kind == TypeKind::FLOAT
                                    ? TypeKind::FLOAT
                                    : (loaded->type.kind ==
                                               TypeKind::SIGNED_INT
                                           ? TypeKind::SIGNED_INT
                                           : TypeKind::UNSIGNED_INT),
                                elementBits, 1};
                            changed |= attachElementType(
                                op.inputs[0], element, values_);
                        }
                    }
                    changed |= constrain(op.output,
                                         {TypeKind::UNSIGNED_INT, bits, 1});
                    break;
                case POp::STORE:
                    if (!op.inputs.empty()) {
                        changed |= constrain(op.inputs[0],
                                             {TypeKind::POINTER, 64, 1});
                        // The stored value's width and kind type the element.
                        // sleigh encodes STORE as in0=addr in2=value (in1 is
                        // unused), so the SSA input list is [addr, 0, value].
                        if (op.inputs.size() > 2) {
                            const SsaValue* stored = value(op.inputs[2]);
                            if (stored && stored->size > 0 &&
                                stored->size <= 8) {
                                DataType element{
                                    stored->type.kind == TypeKind::FLOAT
                                        ? TypeKind::FLOAT
                                        : (stored->type.kind ==
                                                   TypeKind::SIGNED_INT
                                               ? TypeKind::SIGNED_INT
                                               : TypeKind::UNSIGNED_INT),
                                    stored->size * 8, 1};
                                changed |= attachElementType(
                                    op.inputs[0], element, values_);
                            }
                        }
                    }
                    break;
                case POp::INT_EQUAL: case POp::INT_NOTEQUAL: case POp::INT_LESS:
                case POp::INT_SLESS: case POp::INT_LESSEQUAL: case POp::INT_SLESSEQUAL:
                case POp::BOOL_NEGATE: case POp::BOOL_XOR: case POp::BOOL_AND:
                case POp::BOOL_OR: case POp::INT_CARRY: case POp::INT_SCARRY:
                case POp::INT_SBORROW: case POp::INT_PARITY:
                case POp::INT_MULT_OVERFLOW: case POp::INT_SMULT_OVERFLOW:
                    changed |= constrain(op.output, {TypeKind::BOOL, 1, 1});
                    break;
                case POp::INT_SEXT:
                    changed |= constrain(op.output, {TypeKind::SIGNED_INT, bits, 1});
                    if (!op.inputs.empty()) changed |= constrain(op.inputs[0], {TypeKind::SIGNED_INT, 0, 1});
                    break;
                case POp::INT_ZEXT:
                    changed |= constrain(op.output, {TypeKind::UNSIGNED_INT, bits, 1});
                    break;
                case POp::INT_ADD: case POp::INT_SUB:
                    if (op.inputs.size() >= 2) {
                        const SsaValue* a = value(op.inputs[0]);
                        const SsaValue* b = value(op.inputs[1]);
                        if ((a && a->type.kind == TypeKind::POINTER) ||
                            (b && b->type.kind == TypeKind::POINTER))
                            changed |= constrain(op.output, {TypeKind::POINTER, bits, 1});
                        else changed |= constrain(op.output, {TypeKind::UNSIGNED_INT, bits, 1});
                        // LOAD/STORE may establish that the arithmetic result
                        // is an address only on a later fixed-point pass.
                        // Push that evidence through base +/- displacement;
                        // otherwise a 64-bit Windows pointer used at one field
                        // can be emitted as uint32_t and truncated at the ABI.
                        const SsaValue* output = value(op.output);
                        if (output && output->type.kind == TypeKind::POINTER) {
                            const bool aConstant = a && a->constant.has_value();
                            const bool bConstant = b && b->constant.has_value();
                            if (!aConstant && (bConstant || op.op == POp::INT_SUB))
                                changed |= constrain(op.inputs[0],
                                    {TypeKind::POINTER, 64, 1});
                            if (op.op == POp::INT_ADD && !bConstant && aConstant)
                                changed |= constrain(op.inputs[1],
                                    {TypeKind::POINTER, 64, 1});
                        }
                    }
                    break;
                case POp::SELECT:
                    if (!op.inputs.empty()) changed |= constrain(op.inputs[0], {TypeKind::BOOL, 1, 1});
                    if (op.inputs.size() == 3) {
                        const SsaValue* a = value(op.inputs[1]);
                        const SsaValue* b = value(op.inputs[2]);
                        if (a && b) changed |= constrain(op.output, mergeType(a->type, b->type));
                    }
                    break;
                case POp::FLOAT_EQUAL: case POp::FLOAT_NOTEQUAL:
                case POp::FLOAT_LESS: case POp::FLOAT_LESSEQUAL:
                case POp::FLOAT_NAN:
                    changed |= constrain(op.output, {TypeKind::BOOL, 1, 1});
                    for (SsaId input : op.inputs)
                        changed |= constrain(input, {TypeKind::FLOAT, 0, 1});
                    break;
                case POp::FLOAT_ADD: case POp::FLOAT_SUB: case POp::FLOAT_MULT:
                case POp::FLOAT_DIV: case POp::FLOAT_NEG: case POp::FLOAT_ABS:
                case POp::FLOAT_SQRT: case POp::FLOAT_MIN: case POp::FLOAT_MAX:
                    changed |= constrain(op.output,
                                         {bits > 64 ? TypeKind::VECTOR : TypeKind::FLOAT,
                                          bits, bits > 64 ? std::max(1, bits / 32) : 1});
                    for (SsaId input : op.inputs)
                        changed |= constrain(input, {TypeKind::FLOAT, 0, 1});
                    break;
                case POp::FLOAT_INT2FLOAT:
                    changed |= constrain(op.output,
                                         {bits > 64 ? TypeKind::VECTOR : TypeKind::FLOAT,
                                          bits, bits > 64 ? 1 : 1});
                    if (!op.inputs.empty())
                        changed |= constrain(op.inputs[0], {TypeKind::SIGNED_INT, 0, 1});
                    if (op.inputs.size() > 1)
                        changed |= constrain(op.inputs[1], {TypeKind::VECTOR, bits, 1});
                    break;
                case POp::FLOAT_FLOAT2INT:
                    changed |= constrain(op.output, {TypeKind::SIGNED_INT, bits, 1});
                    if (!op.inputs.empty())
                        changed |= constrain(op.inputs[0], {TypeKind::FLOAT, 0, 1});
                    break;
                case POp::FLOAT_FLOAT2FLOAT:
                    changed |= constrain(op.output,
                                         {bits > 64 ? TypeKind::VECTOR : TypeKind::FLOAT,
                                          bits, bits > 64 ? 1 : 1});
                    for (SsaId input : op.inputs)
                        changed |= constrain(input, {TypeKind::FLOAT, 0, 1});
                    break;
                case POp::SIMD_MASK:
                    changed |= constrain(op.output, {TypeKind::VECTOR, bits, 1});
                    if (op.inputs.size() > 2)
                        changed |= constrain(op.inputs[2],
                                             {TypeKind::UNSIGNED_INT, 64, 1});
                    break;
                default:
                    if (op.output) changed |= constrain(op.output, {TypeKind::UNSIGNED_INT, bits, 1});
                    break;
                }
            }
        }
    }

    // Recover aggregate pointees from constant-offset accesses rooted at an
    // entry ABI value.  Repeated equal-stride fields become arrays, aliasing
    // fields become unions, and otherwise a synthetic structure is created.
    std::map<SsaId, std::pair<SsaId, int64_t>> provenance;
    for (const auto& parameter : parameters_) {
        const SsaValue* v = value(parameter.second);
        if (v && v->storage == SsaValue::REGISTER)
            provenance[parameter.second] = {parameter.second, 0};
    }
    // WS3: call results are also field-evidence roots.  A factory/allocator
    // return held in the return register and dereferenced at constant
    // offsets carries the same layout information as a pointer parameter;
    // seed it so the fixed point below propagates through result copies.
    for (const SsaBlock& block : blocks_)
        for (const SsaOp& op : block.ops)
            if ((op.op == POp::CALL || op.op == POp::CALLIND) && op.output)
                provenance[op.output] = {op.output, 0};
    for (int pass = 0; pass < 8; ++pass) {
        bool progress = false;
        for (const SsaBlock& block : blocks_) {
            // WS3: propagate provenance through block-boundary phis.  A call
            // result dereferenced in a successor block reaches the LOAD only
            // via a phi of the call output, which the op-only propagation
            // below never sees.  Require every incoming value to agree on
            // (root, delta) so conflicting merges stay anonymous.
            auto propagatePhi = [&](const SsaOp& phi) {
                if (!phi.output || phi.inputs.empty()) return;
                const auto first = provenance.find(phi.inputs[0]);
                if (first == provenance.end()) return;
                for (size_t i = 1; i < phi.inputs.size(); ++i) {
                    const auto it = provenance.find(phi.inputs[i]);
                    if (it == provenance.end() || it->second != first->second)
                        return;
                }
                progress |=
                    provenance.emplace(phi.output, first->second).second;
            };
            for (const SsaOp& phi : block.phis) propagatePhi(phi);
            for (const SsaOp& op : block.ops) {
                if (op.phi) propagatePhi(op);
                if (!op.output || op.inputs.empty()) continue;
                if (op.op == POp::COPY && provenance.count(op.inputs[0]))
                    progress |= provenance.emplace(op.output,
                                                   provenance[op.inputs[0]]).second;
                if ((op.op != POp::INT_ADD && op.op != POp::INT_SUB) ||
                    op.inputs.size() < 2)
                    continue;
                for (int side = 0; side < 2; ++side) {
                    const SsaId base = op.inputs[side];
                    const SsaValue* displacement = value(op.inputs[1 - side]);
                    if (!provenance.count(base) || !displacement ||
                        !displacement->constant)
                        continue;
                    int64_t delta = static_cast<int64_t>(*displacement->constant);
                    if (op.op == POp::INT_SUB && side == 0) delta = -delta;
                    else if (op.op == POp::INT_SUB) continue;
                    auto derived = provenance[base];
                    derived.second += delta;
                    progress |= provenance.emplace(op.output, derived).second;
                }
            }
        }
        if (!progress) break;
    }
    std::map<SsaId, std::vector<TypeField>> accessedFields;
    for (const SsaBlock& block : blocks_)
        for (const SsaOp& op : block.ops) {
            if ((op.op != POp::LOAD && op.op != POp::STORE) || op.inputs.empty() ||
                !provenance.count(op.inputs[0]))
                continue;
            const auto origin = provenance[op.inputs[0]];
            if (origin.second < 0) continue;
            const SsaValue* fieldValue = op.op == POp::LOAD
                                             ? value(op.output)
                                             : (op.inputs.size() > 2
                                                    ? value(op.inputs[2]) : nullptr);
            if (!fieldValue) continue;
            accessedFields[origin.first].push_back(
                {"field_" + std::to_string(origin.second),
                 static_cast<uint64_t>(origin.second), fieldValue->type});
        }
    for (auto& entry : accessedFields) {
        auto& fields = entry.second;
        // The same (offset, type) pair is recorded once per memory op, so
        // repeated accesses to one field emitted duplicate members (e.g.
        // four "uint32_t field_8;" lines).  Only distinct observations
        // carry layout information - deduplicate before the analysis.
        std::sort(fields.begin(), fields.end(), [](const TypeField& a,
                                                   const TypeField& b) {
            return std::tie(a.byteOffset, a.name, a.type.bits) <
                   std::tie(b.byteOffset, b.name, b.type.bits);
        });
        fields.erase(std::unique(fields.begin(), fields.end(),
                                 [](const TypeField& a, const TypeField& b) {
                                     return a.byteOffset == b.byteOffset &&
                                            a.name == b.name &&
                                            a.type.bits == b.type.bits;
                                 }),
                     fields.end());
        // One constant-offset dereference is already sufficient to establish
        // that an ABI live-in is an address.  Multiple observations are only
        // required to choose between struct/array/union layout patterns.
        // Requiring two fields truncated single-field objects such as the
        // Windows CONTEXT pointer passed to RtlCaptureContext to uint32_t.
        if (fields.empty()) continue;
        // Phase 7: a single narrow access is scalar dereference evidence -
        // the pointer element type attached by LOAD/STORE inference is more
        // precise than a synthetic single-field struct.  Scalar and SSE
        // scalar accesses are <=128 bits; only wide struct blits (>=16
        // bytes of payload, e.g. CONTEXT-style stores) aggregate.
        if (fields.size() == 1 && fields[0].type.bits <= 128) continue;
        std::sort(fields.begin(), fields.end(), [](const TypeField& a,
                                                   const TypeField& b) {
            return std::tie(a.byteOffset, a.name) < std::tie(b.byteOffset, b.name);
        });
        bool overlaps = false;
        for (size_t i = 1; i < fields.size(); ++i)
            overlaps |= fields[i - 1].byteOffset == fields[i].byteOffset &&
                        fields[i - 1].type != fields[i].type;
        bool array = fields.size() >= 3 && !overlaps;
        uint64_t stride = array ? fields[1].byteOffset - fields[0].byteOffset : 0;
        for (size_t i = 1; array && i < fields.size(); ++i)
            array &= stride != 0 && fields[i].byteOffset - fields[i - 1].byteOffset ==
                                      stride && fields[i].type == fields[0].type;

        auto aggregateDetail = std::make_shared<TypeDetail>();
        aggregateDetail->name = "recovered_" + std::to_string(entry.first);
        DataType aggregate;
        if (array) {
            aggregate.kind = TypeKind::ARRAY;
            aggregateDetail->elementType = std::make_shared<DataType>(fields[0].type);
            aggregateDetail->elementCount = fields.size();
        } else {
            aggregate.kind = overlaps ? TypeKind::UNION : TypeKind::STRUCT;
            aggregateDetail->fields = fields;
        }
        aggregate.detail = aggregateDetail;
        const TypeField& last = fields.back();
        aggregate.bits = static_cast<int>((last.byteOffset +
                                           std::max(1, last.type.bits / 8)) * 8);
        DataType pointer{TypeKind::POINTER, 64, 1};
        pointer.detail = std::make_shared<TypeDetail>();
        pointer.detail->elementType = std::make_shared<DataType>(aggregate);
        values_[entry.first].type = std::move(pointer);
    }
    // WS3: recovered_* aggregate names are keyed by SSA id, which is only
    // unique within one function.  Two functions recovered into one
    // translation unit would emit colliding definitions with different
    // layouts.  Prefix every synthetic aggregate name with this function's
    // entry address so names stay globally unique.
    if (!blocks_.empty()) {
        char prefixBuf[48];
        std::snprintf(prefixBuf, sizeof(prefixBuf), "recovered_%llx_",
                      static_cast<unsigned long long>(blocks_.front().start));
        const std::string prefix = prefixBuf;
        std::set<TypeDetail*> renamed;
        std::function<void(DataType&)> uniquify;
        uniquify = [&](DataType& type) {
            if (type.detail) {
                if (type.detail->name.rfind("recovered_", 0) == 0 &&
                    type.detail->name.rfind(prefix, 0) != 0 &&
                    renamed.insert(type.detail.get()).second)
                    type.detail->name =
                        prefix + type.detail->name.substr(10);
                if (type.detail->elementType)
                    uniquify(*type.detail->elementType);
                for (TypeField& field : type.detail->fields)
                    uniquify(field.type);
            }
        };
        for (auto& kv : values_) uniquify(kv.second.type);
    }
    // WS3: export struct layouts recovered for call results so the emitter
    // can name members on locals holding factory/allocator returns.  The
    // layout attaches to the base of an address chain, which may be a copy
    // of the call output rather than the output itself, so follow the
    // provenance chain to the root before attributing.
    callResultTypes_.clear();
    std::map<SsaId, uint64_t> callOutputAddress;
    for (const SsaBlock& block : blocks_)
        for (const SsaOp& op : block.ops)
            if ((op.op == POp::CALL || op.op == POp::CALLIND) &&
                op.output)
                callOutputAddress[op.output] = op.address;
    for (const auto& kv : values_) {
        const DataType& type = kv.second.type;
        if (type.kind != TypeKind::POINTER || !type.detail ||
            !type.detail->elementType)
            continue;
        const DataType& element = *type.detail->elementType;
        if (element.kind != TypeKind::STRUCT &&
            element.kind != TypeKind::UNION)
            continue;
        SsaId root = kv.first;
        for (int hop = 0; hop < 16; ++hop) {
            const auto pit = provenance.find(root);
            if (pit == provenance.end()) break;
            root = pit->second.first;
        }
        const auto callIt = callOutputAddress.find(root);
        if (callIt == callOutputAddress.end()) continue;
        callResultTypes_.emplace(callIt->second, element);
    }
}

FunctionSignature FunctionIR::inferSignature() const {
    FunctionSignature sig;
    const auto abiArgs = abiArguments(arch_, callingConvention_);
    std::vector<uint64_t> returnRegs;
    if (arch_.rfind("x86", 0) == 0) {
        returnRegs = {0, 2 * 8};
    } else if (arch_.rfind("riscv", 0) == 0) {
        returnRegs = {10 * 8, 11 * 8};
    } else if (arch_ == "aarch64" || arch_ == "arm64") {
        returnRegs = {0, 8};
    } else {
        returnRegs = {0, 8};
    }

    std::set<SsaId> used;
    for (const auto& block : blocks_) {
        for (const auto& op : block.ops) used.insert(op.inputs.begin(), op.inputs.end());
    }
    bool grew = true;
    while (grew) {
        grew = false;
        for (const auto& block : blocks_)
            for (const auto& phi : block.phis) {
                if (!used.count(phi.output)) continue;
                for (SsaId input : phi.inputs) grew |= used.insert(input).second;
            }
    }
    for (const auto& arg : abiArgs) {
        DataType mergedType;
        SsaId representative = 0;
        int widestBytes = 0;
        for (const auto& param : parameters_) {
            if (param.first.first != arg.first || !used.count(param.second)) continue;
            const SsaValue& v = values_.at(param.second);
            DataType viewType = v.type.kind == TypeKind::UNKNOWN
                ? DataType{TypeKind::UNSIGNED_INT, v.size * 8, 1}
                : v.type;
            mergedType = mergeType(mergedType, viewType);
            if (v.size > widestBytes) {
                widestBytes = v.size;
                representative = param.second;
            }
        }
        // x86 subregisters share one architectural ABI argument.  ECX and
        // RCX can both have live-in SSA values in a function; choosing the
        // first map entry silently preferred the 32-bit view and truncated
        // pointers.  Merge every used view and retain the widest SSA value.
        if (representative)
            sig.parameters.push_back({arg.second, arg.first, representative,
                                      mergedType});
    }

    for (const auto& stack : stackInputs_) {
        if (!used.count(stack.second)) continue;
        const SsaValue& value = values_.at(stack.second);
        const DataType type = value.type.kind == TypeKind::UNKNOWN
                                  ? DataType{TypeKind::UNSIGNED_INT,
                                             value.size * 8, 1}
                                  : value.type;
        sig.parameters.push_back({"stack_arg" +
                                      std::to_string(sig.parameters.size()),
                                  0, stack.second, type, true, stack.first});
    }

    if (hasTailCall_) {
        // A tail-call board (`mov reg,[slot]; jmp *reg`) never reads its
        // ABI argument registers in its own body, so the usage scan above
        // drops them and the function is inferred with no parameters.  The
        // dispatch then forwards zeros instead of the caller's registers:
        // an allocator board called with its size in rcx would allocate 0
        // bytes (or dispatch with a NULL first argument).  Preserve every
        // ABI argument register that the body does not already declare so
        // the tail call forwards the caller's original arguments.
        for (const auto& arg : abiArgs) {
            const bool already = std::any_of(
                sig.parameters.begin(), sig.parameters.end(),
                [&](const FunctionParameter& p) {
                    return p.registerOffset == arg.first;
                });
            if (!already)
                sig.parameters.push_back(
                    {arg.second, arg.first, 0,
                     DataType{TypeKind::UNSIGNED_INT, 64, 1}});
        }
    }

    std::map<uint64_t, DataType> returnedComponents;
    for (const SsaBlock& block : blocks_) {
        bool returns = false;
        for (const SsaOp& op : block.ops) if (op.op == POp::RETURN) returns = true;
        if (!returns) continue;
        for (const auto& state : outgoing_) {
            if (state.first != block.start) continue;
            for (const auto& reg : state.second) {
                if (std::find(returnRegs.begin(), returnRegs.end(),
                              reg.first.first) == returnRegs.end())
                    continue;
                const SsaValue& v = values_.at(reg.second);
                if (v.version == 0) continue;
                if (reg.first.first != returnRegs.front()) {
                    bool definedHere = false;
                    for (const SsaOp& op : block.ops)
                        definedHere |= op.output == v.id;
                    if (!definedHere) continue;
                }
                sig.returnValues.push_back(v.id);
                returnedComponents[reg.first.first] =
                    mergeType(returnedComponents[reg.first.first], v.type);
            }
        }
    }
    if (returnedComponents.empty() && hasTailCall_) {
        // A tail jump returns exactly what its target returns.  Until the
        // external/import prototype is known, preserving the machine return
        // register is safer than erasing it as void.
        sig.returnType = {TypeKind::UNSIGNED_INT, 64, 1};
        sig.returnComponents.push_back(sig.returnType);
    } else if (returnedComponents.size() == 1) {
        sig.returnType = returnedComponents.begin()->second;
        if (sig.returnType.kind == TypeKind::UNKNOWN)
            sig.returnType = {TypeKind::UNSIGNED_INT, 64, 1};
        sig.returnComponents.push_back(sig.returnType);
    } else if (returnedComponents.size() > 1) {
        auto detail = std::make_shared<TypeDetail>();
        detail->name = "return_pair";
        int bits = 0;
        size_t index = 0;
        for (const auto& component : returnedComponents) {
            DataType type = component.second;
            if (type.kind == TypeKind::UNKNOWN)
                type = {TypeKind::UNSIGNED_INT, 64, 1};
            sig.returnComponents.push_back(type);
            detail->fields.push_back({"part" + std::to_string(index++),
                                      static_cast<uint64_t>(bits / 8), type});
            bits += std::max(64, type.bits);
        }
        sig.returnType = {TypeKind::STRUCT, bits, 1};
        sig.returnType.detail = std::move(detail);
    }
    return sig;
}

void FunctionIR::optimize() {
    std::map<SsaId, SsaId> replace;
    auto canonical = [&](SsaId id) {
        while (replace.count(id)) id = replace[id];
        return id;
    };
    for (SsaBlock& block : blocks_) {
        // Local value numbering is deliberately block-scoped until MidIR has
        // a full dominator-tree GVN pass.  Reusing a value from an unrelated
        // predecessor is not valid SSA optimization.
        std::map<std::tuple<POp, SsaId, SsaId>, SsaId> expressions;
        for (SsaOp& op : block.ops) {
            for (SsaId& input : op.inputs) input = canonical(input);
            if (!op.output || !pure(op.op)) continue;
            SsaValue& output = values_.at(op.output);
            if (op.op == POp::COPY && op.inputs.size() == 1) {
                replace[op.output] = op.inputs[0]; op.removed = true; continue;
            }
            if (op.inputs.size() == 2) {
                const SsaValue* a = value(op.inputs[0]);
                const SsaValue* b = value(op.inputs[1]);
                if (a && b && a->constant && b->constant) {
                    if (auto result = fold(op.op, *a->constant, *b->constant, output.size)) {
                        output.constant = *result;
                        output.storage = SsaValue::CONSTANT;
                        op.removed = true;
                        continue;
                    }
                }
                if (b && b->constant) {
                    const uint64_t k = *b->constant;
                    if ((op.op == POp::INT_ADD || op.op == POp::INT_SUB ||
                         op.op == POp::INT_OR || op.op == POp::INT_XOR) && k == 0) {
                        replace[op.output] = op.inputs[0]; op.removed = true; continue;
                    }
                    if (op.op == POp::INT_MULT && k == 1) {
                        replace[op.output] = op.inputs[0]; op.removed = true; continue;
                    }
                    if (op.op == POp::INT_AND && k == maskFor(output.size)) {
                        replace[op.output] = op.inputs[0]; op.removed = true; continue;
                    }
                }
                auto key = std::make_tuple(op.op, op.inputs[0], op.inputs[1]);
                const auto found = expressions.find(key);
                if (found != expressions.end() && output.storage == SsaValue::TEMPORARY) {
                    replace[op.output] = found->second; op.removed = true;
                } else expressions[key] = op.output;
            }
        }
    }
    // Alias-aware load forwarding.  A store only invalidates earlier loads
    // whose byte ranges may overlap; stores to proven-disjoint stack/global
    // objects no longer destroy all memory knowledge.
    const AliasAnalysis aliases(*this);
    for (SsaBlock& block : blocks_) {
        std::vector<SsaOp*> availableLoads;
        for (SsaOp& op : block.ops) {
            for (SsaId& input : op.inputs) input = canonical(input);
            if (op.removed) continue;
            if (op.op == POp::CALL || op.op == POp::CALLIND ||
                op.op == POp::SYSCALL) {
                availableLoads.clear();
                continue;
            }
            if (op.op == POp::STORE) {
                availableLoads.erase(
                    std::remove_if(availableLoads.begin(), availableLoads.end(),
                                   [&](const SsaOp* load) {
                                       return aliases.mayClobber(op, *load);
                                   }),
                    availableLoads.end());
                continue;
            }
            if (op.op != POp::LOAD || op.inputs.empty() || !op.output) continue;
            const SsaValue* output = value(op.output);
            const uint64_t size = output && output->size > 0
                                      ? static_cast<uint64_t>(output->size) : 0;
            bool forwarded = false;
            for (auto it = availableLoads.rbegin(); it != availableLoads.rend(); ++it) {
                const SsaOp* previous = *it;
                const SsaValue* previousOutput = value(previous->output);
                const uint64_t previousSize = previousOutput && previousOutput->size > 0
                                                  ? static_cast<uint64_t>(previousOutput->size)
                                                  : 0;
                if (size == previousSize &&
                    aliases.alias(op.inputs[0], size,
                                  previous->inputs[0], previousSize) ==
                        AliasResult::MUST_ALIAS) {
                    replace[op.output] = canonical(previous->output);
                    op.removed = true;
                    forwarded = true;
                    break;
                }
            }
            if (!forwarded) availableLoads.push_back(&op);
        }
    }
    for (SsaBlock& block : blocks_) {
        for (SsaOp& phi : block.phis) for (SsaId& input : phi.inputs) input = canonical(input);
        for (SsaOp& op : block.ops) for (SsaId& input : op.inputs) input = canonical(input);
    }
    std::map<SsaId, size_t> uses;
    for (const SsaBlock& block : blocks_) {
        for (const SsaOp& phi : block.phis) for (SsaId id : phi.inputs) ++uses[id];
        for (const SsaOp& op : block.ops) for (SsaId id : op.inputs) ++uses[id];
    }
    for (SsaBlock& block : blocks_)
        for (SsaOp& op : block.ops) {
            const SsaValue* out = value(op.output);
            if (!op.removed && out && out->storage == SsaValue::TEMPORARY &&
                uses[op.output] == 0 && pure(op.op)) op.removed = true;
        }
}

std::vector<JumpTable> recoverJumpTables(const CfgBuilder& cfg,
                                         const MemoryImage& memory,
                                         int pointerSize, size_t maxEntries) {
    std::vector<JumpTable> result;
    if (pointerSize != 4 && pointerSize != 8) return result;
    for (const CfgBlock& block : cfg.blocks()) {
        for (const PcodeInsn& insn : block.insns) {
            std::map<uint64_t, const PcodeOp*> defs;
            for (const PcodeOp& op : insn.ops) if (op.out) defs[op.out] = &op;
            for (const PcodeOp& branch : insn.ops) {
                if (branch.op != POp::BRANCHIND &&
                    !(branch.op == POp::BRANCH &&
                      (!insn.find(branch.in0) || !insn.find(branch.in0)->isConst())))
                    continue;
                uint64_t root = branch.in0;
                std::set<uint64_t> chased;
                while (defs.count(root) && defs[root]->op == POp::COPY &&
                       chased.insert(root).second)
                    root = defs[root]->in0;
                if (defs.count(root) && defs[root]->op == POp::LOAD) root = defs[root]->in0;
                uint64_t base = 0;
                bool haveBase = false;
                const Varnode* direct = insn.find(root);
                if (direct && direct->isConst()) { base = direct->offset; haveBase = true; }
                if (defs.count(root) && defs[root]->op == POp::INT_ADD) {
                    for (uint64_t id : {defs[root]->in0, defs[root]->in1}) {
                        const Varnode* v = insn.find(id);
                        if (v && v->isConst()) { base = v->offset; haveBase = true; }
                    }
                }
                if (!haveBase || !memory.isReadable(base)) continue;
                JumpTable table;
                table.dispatchAddress = insn.addr; table.tableAddress = base;
                table.entrySize = pointerSize;
                for (size_t i = 0; i < maxEntries; ++i) {
                    uint64_t raw = 0;
                    if (!memory.read(base + i * pointerSize, &raw, pointerSize)) break;
                    if (pointerSize == 4) raw &= 0xffffffffULL;
                    uint64_t target = raw;
                    if (i == 0 && !memory.isExecutable(target) && pointerSize == 4) {
                        const int64_t displacement = static_cast<int32_t>(raw);
                        if ((displacement >= 0 &&
                             static_cast<uint64_t>(displacement) <=
                                 std::numeric_limits<uint64_t>::max() - base) ||
                            (displacement < 0 &&
                             static_cast<uint64_t>(-displacement) <= base)) {
                            target = displacement >= 0
                                         ? base + static_cast<uint64_t>(displacement)
                                         : base - static_cast<uint64_t>(-displacement);
                            table.relative = memory.isExecutable(target);
                        }
                    } else if (table.relative) {
                        const int64_t displacement = static_cast<int32_t>(raw);
                        if (displacement >= 0 &&
                            static_cast<uint64_t>(displacement) <=
                                std::numeric_limits<uint64_t>::max() - base)
                            target = base + static_cast<uint64_t>(displacement);
                        else if (displacement < 0 &&
                                 static_cast<uint64_t>(-displacement) <= base)
                            target = base - static_cast<uint64_t>(-displacement);
                        else break;
                    }
                    if (!memory.isExecutable(target)) break;
                    table.targets.push_back(target);
                }
                if (table.targets.size() >= 2) result.push_back(std::move(table));
            }
        }
    }
    return result;
}

bool FunctionEffects::mergeFrom(const FunctionEffects& other) {
    const FunctionEffects before = *this;
    readsMemory |= other.readsMemory;
    writesMemory |= other.writesMemory;
    allocates |= other.allocates;
    frees |= other.frees;
    unknownCall |= other.unknownCall;
    referencedObjects.insert(other.referencedObjects.begin(),
                             other.referencedObjects.end());
    modifiedObjects.insert(other.modifiedObjects.begin(),
                           other.modifiedObjects.end());
    return readsMemory != before.readsMemory ||
           writesMemory != before.writesMemory ||
           allocates != before.allocates || frees != before.frees ||
           unknownCall != before.unknownCall ||
           referencedObjects != before.referencedObjects ||
           modifiedObjects != before.modifiedObjects;
}

const AnalyzedFunction* ProgramAnalysis::functionAt(uint64_t address) const {
    const auto found = functions_.find(address);
    return found == functions_.end() ? nullptr : &found->second;
}

std::optional<FunctionEffects> ProgramAnalysis::effectsAt(
    uint64_t address) const {
    const AnalyzedFunction* function = functionAt(address);
    return function ? std::optional<FunctionEffects>(function->effects)
                    : std::nullopt;
}

std::optional<FunctionSignature> ProgramAnalysis::signatureAt(
    uint64_t address) const {
    const AnalyzedFunction* function = functionAt(address);
    if (function) return function->signature;
    // Phase 6: imported targets carry call-site-recovered prototypes.
    const auto imported = importPrototypes_->prototypeFor(address);
    if (imported) return imported->signature;
    return std::nullopt;
}

const ImportPrototypeRecovery& ProgramAnalysis::importPrototypes() const {
    return *importPrototypes_;
}

ProgramAnalysis::~ProgramAnalysis() = default;

bool ProgramAnalysis::build(const Program& program, const SleighEngine& engine,
                            const std::string& callingConvention,
                            size_t maximumFunctions) {
    architecture_ = program.arch;
    callingConvention_ = callingConvention;
    functions_.clear();
    if (!importPrototypes_) importPrototypes_ = std::make_unique<ImportPrototypeRecovery>();
    cppTypes_ = recoverCppTypes(program);

    const std::shared_ptr<const SleighEngine> engineReference(
        &engine, [](const SleighEngine*) {});
    SpecDisassembler disassembler(engineReference);
    const std::vector<Function> discovered = findFunctions(program, &disassembler);
    if (discovered.empty()) return false;

    auto read = [&](uint64_t address, void* output, size_t size) {
        return program.memory.read(address, output, size);
    };
    auto executable = [&](uint64_t address) {
        return program.memory.isExecutable(address);
    };
    std::map<uint64_t, std::string> importNamesByIat;
    for (const ImportSymbol& imported : program.imports)
        if (!imported.byOrdinal)
            importNamesByIat[imported.iatAddress] = imported.name;
    std::map<uint64_t, const Symbol*> functionSymbolsByAddress;
    for (const Symbol& symbol : program.symbols)
        if (symbol.isFunction && symbol.addr)
            functionSymbolsByAddress.emplace(symbol.addr, &symbol);

    // A bounded analysis must still contain the binary's real entry point.
    // Large PE images commonly place CRT startup far above thousands of
    // unwind-discovered helpers, so taking the first N addresses alone made a
    // generated project structurally incapable of exposing its true entry.
    std::map<uint64_t, const Function*> discoveredByAddress;
    for (const Function& function : discovered)
        discoveredByAddress.emplace(function.addr, &function);
    std::vector<const Function*> selected;
    std::deque<Function> dynamicallyDiscovered;
    std::set<uint64_t> queued;
    const bool bounded = maximumFunctions && discovered.size() > maximumFunctions;
    size_t nextOrdinary = 0;
    auto queueFunction = [&](const Function* function) {
        if (!function || !queued.insert(function->addr).second)
            return false;
        selected.push_back(function);
        return true;
    };
    auto ensureDiscovered = [&](uint64_t address) -> const Function* {
        const auto known = discoveredByAddress.find(address);
        if (known != discoveredByAddress.end()) return known->second;
        if (!program.memory.isExecutable(address)) return nullptr;
        Function function;
        char name[32];
        std::snprintf(name, sizeof(name),
                      architecture_.rfind("x86", 0) == 0 &&
                              architecture_ != "x86"
                          ? "FUN_%016llX" : "FUN_%08llX",
                      static_cast<unsigned long long>(address));
        function.name = name;
        function.addr = address;
        function.src = Function::SCAN;
        uint64_t limit = std::numeric_limits<uint64_t>::max();
        const auto next = discoveredByAddress.upper_bound(address);
        if (next != discoveredByAddress.end()) limit = next->first;
        if (const MemoryBlock* block = program.memory.blockAt(address))
            limit = std::min(limit, block->end());
        if (limit > address) function.size = limit - address;
        dynamicallyDiscovered.push_back(std::move(function));
        const Function* inserted = &dynamicallyDiscovered.back();
        discoveredByAddress.emplace(address, inserted);
        return inserted;
    };
    if (!bounded) {
        for (const Function& function : discovered) queueFunction(&function);
    } else {
        const auto entry = discoveredByAddress.find(program.entryPoint);
        if (entry != discoveredByAddress.end()) queueFunction(entry->second);
        else if (!discovered.empty()) queueFunction(&discovered.front());
    }
    // Windows invokes PE TLS callbacks before the executable entry point.
    // They therefore form startup roots just like the real entry and must not
    // be displaced by low-address helpers in a bounded large-program run.
    if (program.tls)
        for (uint64_t callback : program.tls->callbacks)
            queueFunction(ensureDiscovered(callback));
    auto isPrologueLike = [&](uint64_t address) {
        uint8_t b[8] = {0};
        for (size_t n = 0; n < sizeof(b); ++n)
            if (!read(address + n, &b[n], 1)) return false;
        if (b[0] >= 0x50 && b[0] <= 0x57) return true;
        if ((b[0] == 0x40 || b[0] == 0x41 || b[0] == 0x44 ||
             b[0] == 0x45) &&
            b[1] >= 0x50 && b[1] <= 0x57)
            return true;
        if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) return true;
        if (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC) return true;
        if (b[0] == 0x48 && b[1] == 0x89 && b[2] == 0x5C &&
            b[3] == 0x24)
            return true;
        if ((b[0] == 0x0F && b[1] == 0x29) ||
            (b[0] == 0x66 && b[1] == 0x0F && b[2] == 0x29))
            return true;
        return false;
    };
    // Allocator-table initializers write function addresses into data slots
    // via `lea rax,[addr]; mov [slot],rax`; the slot bytes are uninitialized
    // garbage, so no data pointer references the target and the pointer scan
    // below never promotes it.  Scanning each queued function's first
    // instructions for rip-relative lea targets promotes prologue-like ones
    // so allocator chains stay inside the bounded selection (dispatch of the
    // slot value then hits instead of returning 0 and crashing memsets).
    auto scanLeaTargets = [&](const Function* queuedFunction,
                              size_t insertAt) {
        uint64_t cur = queuedFunction->addr;
        unsigned scannedInsns = 0;
        std::set<uint64_t> visited;
        while (scannedInsns++ < 16 && program.memory.isExecutable(cur)) {
            if (!visited.insert(cur).second) break;
            Insn insn;
            if (!disassembler.disasmOne(program.memory, cur, insn)) break;
            const std::vector<uint8_t>& raw = insn.bytes;
            for (size_t i = 0; i + 7 <= raw.size(); ++i) {
                if (raw[i] != 0x48 || raw[i + 1] != 0x8D) continue;
                const uint8_t modrm = raw[i + 2];
                if ((modrm & 0xC7) != 0x05) continue;
                int32_t disp = 0;
                std::memcpy(&disp, &raw[i + 3], 4);
                const uint64_t target =
                    cur + i + 7 + static_cast<uint64_t>(disp);
                if (!executable(target)) continue;
                if (queued.count(target)) continue;
                if (!isPrologueLike(target)) continue;
                const Function* promoted = ensureDiscovered(target);
                if (!promoted) continue;
                queued.insert(target);
                if (insertAt != static_cast<size_t>(-1)) {
                    // Insert right after the current analysis slot so the
                    // allocator target is analyzed in this bounded run;
                    // pop the tail (a low-priority unwind helper) to stay
                    // within maximumFunctions.
                    selected.insert(selected.begin() + insertAt, promoted);
                    if (selected.size() > maximumFunctions)
                        selected.pop_back();
                } else {
                    selected.push_back(promoted);
                }
            }
            if (insn.kind == Insn::RET) break;
            if (insn.kind == Insn::JMP && insn.targetKnown &&
                executable(insn.target)) {
                cur = insn.target;
            } else {
                cur += insn.size;
            }
        }
    };
    // .pdata (unwind) entries are authoritative compiler-generated function
    // boundaries.  Allocator/CRT helpers (e.g. Blender's 0x140B0xxxx operator
    // new chain) usually appear here with no .data/.rdata pointer to them, so
    // the data-slot scan below never promotes them and a bounded selection
    // drops them - then dispatch of the allocator-table slot values misses
    // and returns 0, crashing downstream memsets.  Queue unwind-discovered
    // functions before the ordinary closure so bounded runs keep them.
    if (bounded) {
        for (const Function& function : discovered) {
            if (function.src != Function::UNWIND) continue;
            if (selected.size() >= maximumFunctions) break;
            queueFunction(&function);
            scanLeaTargets(&function, static_cast<size_t>(-1));
        }
    }
    // Stripped PE images routinely call through global function-pointer slots
    // (call qword ptr [.data+0x...]).  Those indirect targets are invisible to
    // the direct-call closure but frequently sit on the startup path
    // (allocators, CRT thunks, vtables).  Promote every readable data pointer
    // that lands on executable memory with a prologue-like byte pattern so a
    // bounded selection still recovers the real indirect callees instead of
    // leaving dispatch misses that return 0 and crash downstream memsets.
    // (Unbounded analyses already include every discovered function, so the
    // extra scan is only meaningful when the selection is bounded.)
    if (bounded) {
        const size_t promotedRootLimit =
            bounded ? std::max<size_t>(1, maximumFunctions / 10)
                    : std::numeric_limits<size_t>::max();
        size_t promotedRoots = 0;
        bool hitLimit = false;
        // Scan writable data blocks (.data, .bss) before read-only ones
        // (.rdata).  Startup allocator slots (operator-new thunks, stack
        // allocators) live in .data on MSVC images and must not be crowded
        // out by the hundreds of vtable pointers that .rdata yields first.
        for (int pass = 0; pass < 2 && !hitLimit; ++pass) {
            for (const MemoryBlock& block : program.memory.blocks()) {
                if (hitLimit) break;
                if (block.perm & static_cast<int>(Perm::X)) continue;
                if (!(block.perm & static_cast<int>(Perm::R))) continue;
                const bool writable =
                    (block.perm & static_cast<int>(Perm::W)) != 0;
                if ((pass == 0) != writable) continue;
                for (uint64_t address = block.base;
                     address + 8 <= block.end() && address + 8 >= address;
                     address += 8) {
                    uint64_t value = 0;
                    if (!read(address, &value, 8)) continue;
                    if (!executable(value)) continue;
                    if (!isPrologueLike(value)) continue;
                    if (queueFunction(ensureDiscovered(value)) &&
                        ++promotedRoots >= promotedRootLimit) {
                        hitLimit = true;
                        break;
                    }
                }
            }
        }
    }
    auto queueOrdinaryWhenIdle = [&](size_t processedIndex) {
        if (!bounded || processedIndex + 1 >= maximumFunctions ||
            processedIndex + 1 < selected.size())
            return;
        while (nextOrdinary < discovered.size()) {
            if (queueFunction(&discovered[nextOrdinary++])) break;
        }
    };
    const bool reportProgress = std::getenv("CENTRIFUGE_ANALYSIS_PROGRESS") != nullptr;
    size_t queuedCrtErrorInitializers = 0;
    size_t queuedCrtNormalInitializers = 0;
    // A few compiler-generated CRT initializers are hundreds of kilobytes
    // long.  Building one monolithic CFG/SSA graph for them is both wasteful
    // and, on real Blender images, can dominate the entire analysis.  Keep
    // their call-graph contribution with a bounded streaming scan and report
    // them explicitly as incomplete until the project emitter outlines them
    // into independently recoverable chunks.
    constexpr uint64_t maximumMonolithicFunctionBytes = 64U * 1024U;
    const auto analysisProfileStarted = std::chrono::steady_clock::now();
    double profiledCfgSeconds = 0.0;
    double profiledIrSeconds = 0.0;
    double profiledPostSeconds = 0.0;
    std::map<uint64_t, std::unique_ptr<CfgBuilder>> prefetchedCfgs;
    std::set<uint64_t> failedCfgs;
    size_t analysisWorkers = std::max<size_t>(
        1, std::thread::hardware_concurrency());
    if (const char* configured = std::getenv("CENTRIFUGE_ANALYSIS_THREADS")) {
        char* parsedEnd = nullptr;
        const unsigned long parsed = std::strtoul(configured, &parsedEnd, 10);
        if (parsedEnd != configured && !*parsedEnd && parsed)
            analysisWorkers = static_cast<size_t>(parsed);
    }
    if (const char* configured = std::getenv("CENTRIFUGE_CFG_THREADS")) {
        char* parsedEnd = nullptr;
        const unsigned long parsed = std::strtoul(configured, &parsedEnd, 10);
        if (parsedEnd != configured && !*parsedEnd && parsed)
            analysisWorkers = static_cast<size_t>(parsed);
    }
    // One in-flight job per worker is the best default for a dynamically
    // growing startup closure: a wider speculative window can analyze
    // ordinary functions that later CRT-root insertion pushes past the
    // bounded selection limit.  Advanced benchmarks may tune this upward.
    size_t cfgPrefetchFactor = 1;
    if (const char* configured = std::getenv("CENTRIFUGE_CFG_PREFETCH_FACTOR")) {
        char* parsedEnd = nullptr;
        const unsigned long parsed = std::strtoul(configured, &parsedEnd, 10);
        if (parsedEnd != configured && !*parsedEnd && parsed && parsed <= 64)
            cfgPrefetchFactor = static_cast<size_t>(parsed);
    }

    // Functions whose body ends in an indirect jump (data-slot jump board
    // or vtable tail call).  decompileTyped promotes a void return back to
    // a 64-bit value for these (the dispatch forwards rax), so the Phase 7
    // void downgrade must skip them or callers see a conflicting prototype.
    std::set<uint64_t> tailDispatchers;
    for (size_t selectedIndex = 0;
         selectedIndex < selected.size() &&
         (!bounded || selectedIndex < maximumFunctions);
         ++selectedIndex) {
        if (std::getenv("CENTRIFUGE_ANALYSIS_PROFILE") &&
            selectedIndex % 250 == 0) {
            const double elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - analysisProfileStarted).count();
            std::fprintf(stderr,
                "[analysis-profile-progress] index=%zu queued=%zu "
                "elapsed=%.3fs cfg=%.3fs ir=%.3fs post=%.3fs\n",
                selectedIndex, selected.size(), elapsed, profiledCfgSeconds,
                profiledIrSeconds, profiledPostSeconds);
            std::fflush(stderr);
        }
        const Function* selectedFunction = selected[selectedIndex];
        // Allocator-table lea promotion for every analyzed function (not just
        // unwind roots): initializers like FUN_14041F270 are SCAN-discovered
        // and write allocator addresses into data slots via lea+store; the
        // promoted targets are inserted right after this slot so they are
        // analyzed in the same bounded run.
        scanLeaTargets(selectedFunction, selectedIndex + 1);
        const Function& function = *selectedFunction;
        const auto functionStarted = std::chrono::steady_clock::now();
        if (reportProgress) {
            std::fprintf(stderr, "[analysis %zu/%zu] begin 0x%llx %s\n",
                         selectedIndex + 1, selected.size(),
                         static_cast<unsigned long long>(function.addr),
                         function.name.c_str());
            std::fflush(stderr);
        }
        auto reportStage = [&](const char* stage) {
            if (!reportProgress) return;
            const double seconds = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - functionStarted).count();
            std::fprintf(stderr, "[analysis %zu/%zu] stage 0x%llx %s %.3fs\n",
                         selectedIndex + 1, selected.size(),
                         static_cast<unsigned long long>(function.addr), stage,
                         seconds);
            std::fflush(stderr);
        };
        AnalyzedFunction analyzed;
        analyzed.function = function;
        uint64_t end = 0;
        if (function.size && function.addr <=
                                 std::numeric_limits<uint64_t>::max() - function.size)
            end = function.addr + function.size;
        if (function.size > maximumMonolithicFunctionBytes) {
            std::set<uint64_t> callees;
            if ((architecture_ == "x86" || architecture_ == "x86-64") &&
                function.size <= std::numeric_limits<size_t>::max()) {
                std::vector<uint8_t> bytes(static_cast<size_t>(function.size));
                if (program.memory.read(function.addr, bytes.data(), bytes.size())) {
                    auto addRelativeTarget = [&](size_t offset) {
                        int32_t displacement = 0;
                        std::memcpy(&displacement, bytes.data() + offset + 1,
                                    sizeof(displacement));
                        const uint64_t next = function.addr + offset + 5;
                        uint64_t target = 0;
                        if (displacement >= 0) {
                            const uint64_t amount =
                                static_cast<uint32_t>(displacement);
                            if (next > std::numeric_limits<uint64_t>::max() - amount)
                                return;
                            target = next + amount;
                        } else {
                            const uint64_t amount = static_cast<uint64_t>(
                                -static_cast<int64_t>(displacement));
                            if (next < amount) return;
                            target = next - amount;
                        }
                        // The byte scan is deliberately accepted only when it
                        // lands on an independently discovered function.  This
                        // filters E8/E9 bytes embedded in immediates or data.
                        if (discoveredByAddress.count(target)) callees.insert(target);
                    };
                    for (size_t offset = 0; offset + 5 <= bytes.size(); ++offset) {
                        if (bytes[offset] == 0xe8)
                            addRelativeTarget(offset);
                        else if (bytes[offset] == 0xe9 &&
                                 offset + 32 >= bytes.size())
                            addRelativeTarget(offset);
                    }
                }
            } else {
                uint64_t cursor = function.addr;
                while (cursor < end) {
                    Insn instruction;
                    if (!disassembler.disasmOne(program.memory, cursor,
                                                instruction) ||
                        instruction.size == 0)
                        break;
                    if ((instruction.kind == Insn::CALL ||
                         instruction.kind == Insn::JMP) &&
                        instruction.targetKnown)
                        callees.insert(instruction.target);
                    if (cursor > std::numeric_limits<uint64_t>::max() -
                                     instruction.size)
                        break;
                    cursor += instruction.size;
                }
            }
            analyzed.callees.assign(callees.begin(), callees.end());
            analyzed.effects.unknownCall = true;
            analyzed.complexityLimited = true;
            analyzed.incompleteReason = "function exceeds monolithic CFG limit";
            size_t insertion = selectedIndex + 1;
            for (uint64_t callee : analyzed.callees) {
                const bool previouslyDiscovered =
                    discoveredByAddress.count(callee) != 0;
                const Function* target = ensureDiscovered(callee);
                if (!target || functions_.count(target->addr)) continue;
                if (!queued.insert(target->addr).second) continue;
                if (previouslyDiscovered && !bounded)
                    selected.push_back(target);
                else {
                    selected.insert(
                        selected.begin() +
                            static_cast<std::ptrdiff_t>(insertion++),
                        target);
                    if (bounded && selected.size() > maximumFunctions)
                        selected.pop_back();
                }
            }
            functions_.emplace(function.addr, std::move(analyzed));
            if (reportProgress) {
                const double seconds = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - functionStarted).count();
                std::fprintf(stderr,
                    "[analysis %zu/%zu] end 0x%llx %.3fs [streamed-large]\n",
                    selectedIndex + 1, selected.size(),
                    static_cast<unsigned long long>(function.addr), seconds);
                std::fflush(stderr);
            }
            queueOrdinaryWhenIdle(selectedIndex);
            continue;
        }
        if (!prefetchedCfgs.count(function.addr) &&
            !failedCfgs.count(function.addr)) {
            struct CfgJob {
                const Function* function = nullptr;
                uint64_t end = 0;
                std::unique_ptr<CfgBuilder> cfg;
                bool built = false;
            };
            std::vector<CfgJob> jobs;
            const size_t selectionLimit = bounded
                ? std::min(selected.size(), maximumFunctions)
                : selected.size();
            const size_t available = selectionLimit - selectedIndex;
            const size_t prefetchSpan = analysisWorkers >
                    std::numeric_limits<size_t>::max() / cfgPrefetchFactor
                ? available
                : std::min(available, analysisWorkers * cfgPrefetchFactor);
            const size_t prefetchLimit = selectedIndex + prefetchSpan;
            for (size_t index = selectedIndex; index < prefetchLimit; ++index) {
                const Function* candidate = selected[index];
                if (!candidate ||
                    candidate->size > maximumMonolithicFunctionBytes ||
                    prefetchedCfgs.count(candidate->addr) ||
                    failedCfgs.count(candidate->addr) ||
                    functions_.count(candidate->addr))
                    continue;
                uint64_t candidateEnd = 0;
                if (candidate->size && candidate->addr <=
                        std::numeric_limits<uint64_t>::max() - candidate->size)
                    candidateEnd = candidate->addr + candidate->size;
                jobs.push_back({candidate, candidateEnd, nullptr, false});
            }
            const auto cfgBatchStarted = std::chrono::steady_clock::now();
            std::atomic<size_t> nextJob{0};
            auto buildCfg = [&]() {
                for (;;) {
                    const size_t index = nextJob.fetch_add(
                        1, std::memory_order_relaxed);
                    if (index >= jobs.size()) break;
                    CfgJob& job = jobs[index];
                    job.cfg = std::make_unique<CfgBuilder>();
                    job.built = job.cfg->build(engine, read,
                        job.function->addr, job.end, executable);
                }
            };
            const size_t batchWorkers = std::min(analysisWorkers, jobs.size());
            std::vector<std::thread> cfgWorkers;
            cfgWorkers.reserve(batchWorkers);
            for (size_t index = 0; index < batchWorkers; ++index)
                cfgWorkers.emplace_back(buildCfg);
            for (std::thread& worker : cfgWorkers) worker.join();
            profiledCfgSeconds += std::chrono::duration<double>(
                std::chrono::steady_clock::now() - cfgBatchStarted).count();
            // Merge in selection order so cache contents and diagnostics are
            // independent of worker scheduling.
            for (CfgJob& job : jobs) {
                if (job.built)
                    prefetchedCfgs.emplace(job.function->addr,
                                           std::move(job.cfg));
                else
                    failedCfgs.insert(job.function->addr);
            }
        }
        if (failedCfgs.erase(function.addr)) {
            functions_.emplace(function.addr, std::move(analyzed));
            queueOrdinaryWhenIdle(selectedIndex);
            continue;
        }
        const auto cachedCfg = prefetchedCfgs.find(function.addr);
        if (cachedCfg == prefetchedCfgs.end()) {
            functions_.emplace(function.addr, std::move(analyzed));
            queueOrdinaryWhenIdle(selectedIndex);
            continue;
        }
        CfgBuilder cfg = std::move(*cachedCfg->second);
        prefetchedCfgs.erase(cachedCfg);
        reportStage("cfg");
        cfg.applyExceptionRegions(program.exceptionRegions);
        const auto irStarted = std::chrono::steady_clock::now();
        FunctionIR ir;
        if (!ir.build(cfg, architecture_, callingConvention_)) {
            profiledIrSeconds += std::chrono::duration<double>(
                std::chrono::steady_clock::now() - irStarted).count();
            functions_.emplace(function.addr, std::move(analyzed));
            queueOrdinaryWhenIdle(selectedIndex);
            continue;
        }
        profiledIrSeconds += std::chrono::duration<double>(
            std::chrono::steady_clock::now() - irStarted).count();
        const auto postStarted = std::chrono::steady_clock::now();
        reportStage("ssa");
        // Constant addresses are already classified as precise globals by
        // AliasAnalysis.  Installing every PE symbol into every FunctionIR
        // made whole-program recovery O(functions * symbols) before a single
        // memory access was inspected (over 43 million object insertions for
        // a 12k-function Blender closure).  Named field objects can be added
        // lazily when a referenced address needs a symbolic label.
        bool memoryModelChanged = false;
        for (const MidBlock& block : ir.blocks())
            for (const MidInstruction& operation : block.ops) {
                if ((operation.op != POp::CALL &&
                     operation.op != POp::CALLIND) ||
                    !operation.output || operation.inputs.empty())
                    continue;
                const MidValue* targetValue = ir.value(operation.inputs[0]);
                if (!targetValue || !targetValue->constant) continue;
                const auto symbol = functionSymbolsByAddress.find(
                    *targetValue->constant);
                const Symbol* targetSymbol = symbol ==
                    functionSymbolsByAddress.end() ? nullptr : symbol->second;
                if (!targetSymbol) continue;
                const std::string& targetName = targetSymbol->name;
                const bool allocator = targetName == "malloc" ||
                    targetName == "calloc" || targetName == "realloc" ||
                    targetName == "operator new" ||
                    targetName.rfind("_Zn", 0) == 0;
                if (!allocator) continue;
                MemoryObject heap;
                heap.kind = MemoryObjectKind::HEAP;
                heap.value = operation.output;
                heap.allocationSite = operation.address;
                heap.name = targetName + "@" +
                            std::to_string(operation.address);
                ir.addMemoryObject(std::move(heap));
                memoryModelChanged = true;
            }
        reportStage("types");
        if (memoryModelChanged) ir.partitionMemory();
        reportStage("memory-ssa");
        analyzed.signature = ir.inferSignature();
        {
            // Phase 5: calling-convention recovery annotates the signature
            // with variadic / hidden-sret facts derived from the SSA IR and
            // the p-code CFG (see calling_convention.cpp).
            const CallConventionFacts convention =
                recoverCallConvention(ir, cfg, architecture_);
            applyCallConvention(convention, analyzed.signature,
                                architecture_);
        }
        {
            std::map<SsaId, const SsaOp*> definitions;
            for (const SsaBlock& block : ir.blocks()) {
                for (const SsaOp& phi : block.phis)
                    if (phi.output) definitions[phi.output] = &phi;
                for (const SsaOp& operation : block.ops)
                    if (operation.output) definitions[operation.output] = &operation;
            }
            // Constant recovery is queried repeatedly for call targets and
            // arguments.  Copying a visiting set down every PHI path makes a
            // large SSA diamond exponential.  Values are immutable within a
            // FunctionIR, so memoize completed proofs and keep only one
            // active recursion set for cycle detection.
            std::map<SsaId, std::optional<uint64_t>> constantCache;
            std::set<SsaId> constantResolving;
            std::function<std::optional<uint64_t>(SsaId)> constantValue;
            constantValue = [&](SsaId id) -> std::optional<uint64_t> {
                if (!id) return std::nullopt;
                const auto cached = constantCache.find(id);
                if (cached != constantCache.end()) return cached->second;
                if (!constantResolving.insert(id).second) return std::nullopt;

                std::optional<uint64_t> result;
                const SsaValue* value = ir.value(id);
                if (value && value->constant) {
                    result = value->constant;
                } else if (value) {
                    const auto definition = definitions.find(id);
                    if (definition != definitions.end()) {
                        const SsaOp& operation = *definition->second;
                        if (operation.phi) {
                            std::optional<uint64_t> merged;
                            bool valid = !operation.inputs.empty();
                            for (SsaId input : operation.inputs) {
                                const auto candidate = constantValue(input);
                                if (!candidate ||
                                    (merged && *merged != *candidate)) {
                                    valid = false;
                                    break;
                                }
                                merged = candidate;
                            }
                            if (valid) result = merged;
                        } else if ((operation.op == POp::COPY ||
                                    operation.op == POp::INT_ZEXT ||
                                    operation.op == POp::INT_SEXT) &&
                                   !operation.inputs.empty()) {
                            result = constantValue(operation.inputs[0]);
                        } else if (operation.inputs.size() >= 2) {
                            const auto left = constantValue(operation.inputs[0]);
                            const auto right = constantValue(operation.inputs[1]);
                            if (left && right)
                                result = fold(operation.op, *left, *right,
                                              value->size > 0 ? value->size : 8);
                        }
                    }
                }
                constantResolving.erase(id);
                constantCache.emplace(id, result);
                return result;
            };
            // Single-pass use index: map every SSA value id to the ops that
            // consume it, so per-call-site prototype queries stay O(uses)
            // instead of O(call sites x function size).
            std::map<SsaId, std::vector<const SsaOp*>> uses;
            for (const SsaBlock& useBlock : ir.blocks())
                for (const SsaOp& useOp : useBlock.ops) {
                    if (useOp.removed) continue;
                    for (SsaId input : useOp.inputs)
                        if (input) uses[input].push_back(&useOp);
                }
            for (const SsaBlock& block : ir.blocks())
                for (const SsaOp& operation : block.ops) {
                    if (operation.op != POp::CALL &&
                        operation.op != POp::CALLIND)
                        continue;
                    AnalyzedCallSite callSite;
                    callSite.address = operation.address;
                    callSite.indirect = operation.op == POp::CALLIND;
                    if (!operation.inputs.empty())
                        callSite.target = constantValue(operation.inputs[0]);
                    // Phase 6: record per-register argument observations and
                    // return-value consumption for prototype recovery.
                    const auto abi = abiArguments(architecture_,
                                                  callingConvention_);
                    callSite.argInfo.resize(abi.size());
                    for (size_t index = 0;
                         index < abi.size() &&
                         index + 1 < operation.inputs.size();
                         ++index) {
                        const SsaId argumentId =
                            operation.inputs[index + 1];
                        const SsaValue* argument = ir.value(argumentId);
                        CallSiteArgInfo& info = callSite.argInfo[index];
                        if (!argument) continue;
                        info.observed = true;
                        info.widthBytes = argument->size;
                        info.type = argument->type;
                        if (argument->constant) {
                            info.constant = true;
                            info.constantValue = *argument->constant;
                        }
                        const auto foundUses = uses.find(argumentId);
                        if (foundUses != uses.end())
                            for (const SsaOp* useOp : foundUses->second)
                                if ((useOp->op == POp::LOAD ||
                                     useOp->op == POp::STORE) &&
                                    !useOp->inputs.empty() &&
                                    useOp->inputs[0] == argumentId)
                                    info.addressUsed = true;
                    }
                    callSite.arguments.clear();
                    // Keep the original constant-value resolution (recursive
                    // def-chain folding); argInfo is an *additional* view for
                    // import prototype recovery and must not weaken it.
                    for (size_t index = 1;
                         index < operation.inputs.size() && index <= 8;
                         ++index) {
                        callSite.arguments.push_back(
                            constantValue(operation.inputs[index]));
                    }
                    // Return-value consumption: find uses of the call output
                    // through the prebuilt use index.
                    if (operation.output) {
                        const auto foundUses = uses.find(operation.output);
                        if (foundUses != uses.end())
                            for (const SsaOp* useOp : foundUses->second) {
                                callSite.returnsValue = true;
                                if (useOp->op == POp::LOAD ||
                                    useOp->op == POp::STORE) {
                                    callSite.returnDereferenced = true;
                                } else if (useOp->op == POp::INT_ADD ||
                                           useOp->op == POp::INT_SUB ||
                                           useOp->op == POp::INT_MULT ||
                                           useOp->op == POp::INT_DIV ||
                                           useOp->op == POp::INT_AND ||
                                           useOp->op == POp::INT_OR ||
                                           useOp->op == POp::INT_XOR ||
                                           useOp->op == POp::INT_LEFT ||
                                           useOp->op == POp::INT_RIGHT) {
                                    callSite.returnArithmetic = true;
                                } else if (useOp->op == POp::CBRANCH ||
                                           useOp->op == POp::BRANCH) {
                                    callSite.returnBoolean = true;
                                }
                            }
                        const SsaValue* result = ir.value(operation.output);
                        if (result) callSite.returnWidthBytes = result->size;
                    }
                    analyzed.callSites.push_back(std::move(callSite));
                }
        }
        static const std::set<std::string> knownVariadic = {
            "printf", "fprintf", "sprintf", "snprintf", "scanf", "sscanf",
            "execl", "execlp", "fcntl", "ioctl"
        };
        analyzed.signature.variadic = knownVariadic.count(function.name) != 0;
        ir.optimize();
        reportStage("optimize");
        analyzed.blocks = ir.blocks().size();
        analyzed.phiNodes = ir.phiCount();
        analyzed.liveOperations = ir.liveOpCount();
        analyzed.callResultTypes = ir.callResultTypes();
        analyzed.complete = true;
        size_t indirectCalls = 0;
        bool hasSystemCall = false;
        for (const MidBlock& block : ir.blocks())
            for (const MidInstruction& operation : block.ops) {
                if (operation.removed) continue;
                MemoryObjectKind objectKind = MemoryObjectKind::UNKNOWN;
                const auto partition =
                    ir.memoryPartitions().find(operation.memoryPartition);
                if (partition != ir.memoryPartitions().end())
                    objectKind = partition->second.kind;
                if (operation.op == POp::LOAD) {
                    analyzed.effects.readsMemory = true;
                    analyzed.effects.referencedObjects.insert(objectKind);
                } else if (operation.op == POp::STORE) {
                    analyzed.effects.writesMemory = true;
                    analyzed.effects.modifiedObjects.insert(objectKind);
                } else if (operation.op == POp::CALLIND) {
                    ++indirectCalls;
                } else if (operation.op == POp::BRANCHIND) {
                    tailDispatchers.insert(function.addr);
                } else if (operation.op == POp::SYSCALL) {
                    hasSystemCall = true;
                }
            }
        if (function.name == "malloc" || function.name == "calloc" ||
            function.name == "realloc" || function.name == "operator new" ||
            function.name.rfind("_Zn", 0) == 0)
            analyzed.effects.allocates = true;
        if (function.name == "free" || function.name == "operator delete" ||
            function.name.rfind("_Zdl", 0) == 0 ||
            function.name.rfind("_Zda", 0) == 0) {
            analyzed.effects.frees = true;
            analyzed.effects.writesMemory = true;
            analyzed.effects.modifiedObjects.insert(MemoryObjectKind::HEAP);
        }
        std::set<uint64_t> callees;
        for (const CfgBlock& block : cfg.blocks()) {
            callees.insert(block.calls.begin(), block.calls.end());
            if (block.tailCallTarget) callees.insert(*block.tailCallTarget);
            // Recover register-relative direct calls such as RISC-V's
            // AUIPC+JALR sequence.  Concrete propagation is deliberately
            // block-local: crossing a join without a phi proof would create
            // false call-graph edges.
            std::map<uint64_t, uint64_t> knownRegisters;
            for (const PcodeInsn& instruction : block.insns) {
                PcodeEvaluator evaluator(instruction);
                evaluator.regs = knownRegisters;
                evaluator.run();
                const bool callLike = instruction.kind == Insn::CALL ||
                    instruction.text.rfind("call", 0) == 0 ||
                    instruction.text.rfind("jalr", 0) == 0;
                if (callLike && evaluator.lastBranchTarget())
                    callees.insert(*evaluator.lastBranchTarget());
                if (callLike)
                    for (const PcodeOp& op : instruction.ops)
                        if (op.op == POp::CALL || op.op == POp::CALLIND)
                            if (const auto target = evaluator.varnodeValue(op.in0))
                                callees.insert(*target);
                for (const PcodeOp& op : instruction.ops) {
                    const Varnode* output = instruction.find(op.out);
                    if (!output || output->kind != Varnode::REGISTER) continue;
                    const auto value = evaluator.varnodeValue(op.out);
                    if (value) knownRegisters[output->offset] = *value;
                    else knownRegisters.erase(output->offset);
                }
            }
        }
        analyzed.callees.assign(callees.begin(), callees.end());
        {
            size_t insertion = selectedIndex + 1;
            for (uint64_t callee : analyzed.callees) {
                const bool previouslyDiscovered =
                    discoveredByAddress.count(callee) != 0;
                const Function* target = ensureDiscovered(callee);
                if (!target || functions_.count(target->addr)) continue;
                if (!queued.insert(target->addr).second) continue;
                if (previouslyDiscovered && !bounded)
                    selected.push_back(target);
                else {
                    selected.insert(
                        selected.begin() +
                            static_cast<std::ptrdiff_t>(insertion++),
                        target);
                    if (bounded && selected.size() > maximumFunctions)
                        selected.pop_back();
                }
            }
        }
        // MSVC's _initterm/_initterm_e receive half-open arrays of function
        // pointers.  These callbacks are data-flow roots, not direct call
        // edges, so prioritize them explicitly in a bounded startup closure.
        // Without this step a project can recover the CRT thunk yet silently
        // omit every C/C++ static initializer it dispatches.
        std::string crtInitializerKind;
        for (uint64_t callee : analyzed.callees) {
            const auto imported = importNamesByIat.find(callee);
            if (imported != importNamesByIat.end() &&
                (imported->second == "_initterm" ||
                 imported->second == "_initterm_e"))
                crtInitializerKind = imported->second;
        }
        if (!crtInitializerKind.empty()) {
            size_t& queuedInitializers = crtInitializerKind == "_initterm_e"
                ? queuedCrtErrorInitializers : queuedCrtNormalInitializers;
            const size_t initializerBudget = !bounded
                ? std::numeric_limits<size_t>::max()
                : crtInitializerKind == "_initterm_e"
                    ? std::max<size_t>(4, maximumFunctions / 32)
                    : std::max<size_t>(8, maximumFunctions / 2);
            size_t insertion = selectedIndex + 1;
            for (const auto& caller : functions_)
                for (const AnalyzedCallSite& callSite : caller.second.callSites) {
                    if (!callSite.target || *callSite.target != function.addr ||
                        callSite.arguments.size() < 2 ||
                        !callSite.arguments[0] || !callSite.arguments[1])
                        continue;
                    const uint64_t first = *callSite.arguments[0];
                    const uint64_t last = *callSite.arguments[1];
                    if (last < first || (last - first) % 8 != 0 ||
                        last - first > 16U * 1024U * 1024U)
                        continue;
                    for (uint64_t cursor = first; cursor < last; cursor += 8) {
                        if (queuedInitializers >= initializerBudget) break;
                        uint64_t callback = 0;
                        if (!program.memory.read(cursor, &callback,
                                                 sizeof(callback)) ||
                            !callback || !program.memory.isExecutable(callback))
                            continue;
                        const Function* target = ensureDiscovered(callback);
                        if (!target || functions_.count(target->addr) ||
                            !queued.insert(target->addr).second)
                            continue;
                        selected.insert(selected.begin() +
                                            static_cast<std::ptrdiff_t>(insertion++),
                                        target);
                        ++queuedInitializers;
                    }
                }
        }
        if (hasSystemCall || indirectCalls > analyzed.callees.size())
            analyzed.effects.unknownCall = true;
        functions_.emplace(function.addr, std::move(analyzed));
        profiledPostSeconds += std::chrono::duration<double>(
            std::chrono::steady_clock::now() - postStarted).count();
        if (reportProgress) {
            const double seconds = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - functionStarted).count();
            std::fprintf(stderr, "[analysis %zu/%zu] end 0x%llx %.3fs\n",
                         selectedIndex + 1, selected.size(),
                         static_cast<unsigned long long>(function.addr), seconds);
            std::fflush(stderr);
        }
        queueOrdinaryWhenIdle(selectedIndex);
    }

    const auto mainAnalysisFinished = std::chrono::steady_clock::now();

    for (const auto& caller : functions_)
        for (uint64_t calleeAddress : caller.second.callees) {
            auto callee = functions_.find(calleeAddress);
            if (callee != functions_.end()) callee->second.callers.push_back(caller.first);
        }
    for (auto& function : functions_) {
        std::sort(function.second.callers.begin(), function.second.callers.end());
        function.second.callers.erase(
            std::unique(function.second.callers.begin(), function.second.callers.end()),
            function.second.callers.end());
    }
    // Interprocedural Mod/Ref reaches a fixed point over recursion and mutual
    // recursion.  Missing direct callees conservatively make the caller
    // unknown, while known callees contribute their object-class effects.
    const auto modRefStarted = std::chrono::steady_clock::now();
    for (size_t pass = 0; pass < functions_.size() + 1; ++pass) {
        bool changed = false;
        for (auto& caller : functions_)
            for (uint64_t calleeAddress : caller.second.callees) {
                const auto callee = functions_.find(calleeAddress);
                if (callee == functions_.end()) {
                    if (!caller.second.effects.unknownCall) {
                        caller.second.effects.unknownCall = true;
                        changed = true;
                    }
                } else {
                    changed |= caller.second.effects.mergeFrom(
                        callee->second.effects);
                }
            }
        if (!changed) break;
    }
    const auto modRefFinished = std::chrono::steady_clock::now();
    refineCppObjectGraph(program, engine, *this, cppTypes_);
    // Phase 6: recover import prototypes from call-site evidence (the import
    // table itself has no machine code; the union of every call site does).
    importPrototypes_->aggregate(*this, program);
    importPrototypes_->applyKnownPrototypes();
    // Phase 7: refine internal callee prototypes from the union of their
    // call sites - the inverse direction of Phase 6 (which only covers
    // imports, whose bodies do not exist).  Iterates to a fixed point like
    // the Mod/Ref pass: every caller's argInfo/return-consumption evidence
    // merges into the callee signature until no signature changes anymore.
    {
        const auto abi = abiArguments(architecture_, callingConvention_);
        struct CalleeEvidence {
            size_t sites = 0;
            std::vector<CallSiteArgInfo> args;
            bool anyReturnValue = false;
            bool returnDereferenced = false;
            bool returnBoolean = false;
            bool returnArithmetic = false;
        };
        for (size_t pass = 0; pass < functions_.size() + 1; ++pass) {
            bool changed = false;
            std::map<uint64_t, CalleeEvidence> evidence;
            for (const auto& callerEntry : functions_) {
                if (!callerEntry.second.complete) continue;
                for (const AnalyzedCallSite& site :
                     callerEntry.second.callSites) {
                    if (!site.target || site.indirect) continue;
                    CalleeEvidence& ev = evidence[*site.target];
                    ++ev.sites;
                    if (ev.args.size() < site.argInfo.size())
                        ev.args.resize(site.argInfo.size());
                    for (size_t i = 0; i < site.argInfo.size(); ++i) {
                        const CallSiteArgInfo& info = site.argInfo[i];
                        CallSiteArgInfo& merged = ev.args[i];
                        merged.observed |= info.observed;
                        merged.widthBytes =
                            std::max(merged.widthBytes, info.widthBytes);
                        merged.addressUsed |= info.addressUsed;
                        if (!info.observed ||
                            info.type.kind == TypeKind::UNKNOWN)
                            continue;
                        if (merged.type.kind == TypeKind::UNKNOWN &&
                            merged.type.bits == 0)
                            merged.type = info.type;
                        else
                            merged.type = mergeType(merged.type, info.type);
                    }
                    ev.anyReturnValue |= site.returnsValue;
                    ev.returnDereferenced |= site.returnDereferenced;
                    ev.returnBoolean |= site.returnBoolean;
                    ev.returnArithmetic |= site.returnArithmetic;
                }
            }
            for (const auto& kv : evidence) {
                const auto fit = functions_.find(kv.first);
                if (fit == functions_.end() || !fit->second.complete)
                    continue;
                FunctionSignature& sig = fit->second.signature;
                // Parameters: pointer evidence upgrades (or installs) a
                // parameter.  Widths are never narrowed here - the callee
                // body's own usage evidence already set them, and a
                // 32-bit-looking caller argument may still carry live
                // upper bits the callee reads.
                for (size_t i = 0;
                     i < kv.second.args.size() && i < abi.size(); ++i) {
                    const CallSiteArgInfo& info = kv.second.args[i];
                    if (!info.observed) continue;
                    FunctionParameter* param = nullptr;
                    for (FunctionParameter& p : sig.parameters)
                        if (!p.onStack &&
                            p.registerOffset == abi[i].first) {
                            param = &p;
                            break;
                        }
                    if (param) {
                        if (info.addressUsed &&
                            param->type.kind != TypeKind::POINTER &&
                            (param->type.kind == TypeKind::UNSIGNED_INT ||
                             param->type.kind == TypeKind::SIGNED_INT ||
                             param->type.kind == TypeKind::UNKNOWN)) {
                            param->type =
                                DataType{TypeKind::POINTER, 64, 1};
                            changed = true;
                        }
                    } else if (info.addressUsed) {
                        // The callee never reads this argument, but every
                        // caller passes something it dereferences: declare
                        // the pointer parameter for the prototype.
                        FunctionParameter added;
                        added.name = "arg" + std::to_string(i);
                        added.registerOffset = abi[i].first;
                        added.type = DataType{TypeKind::POINTER, 64, 1};
                        sig.parameters.push_back(added);
                        changed = true;
                    }
                }
                // Keep register parameters in ABI order: parameters added
                // from evidence append at the end, and positional call
                // emission requires declaration order to match.
                std::stable_sort(
                    sig.parameters.begin(), sig.parameters.end(),
                    [&](const FunctionParameter& a,
                        const FunctionParameter& b) {
                        auto abiIndex = [&](const FunctionParameter& p) {
                            if (p.onStack) return abi.size() + 1;
                            for (size_t i = 0; i < abi.size(); ++i)
                                if (abi[i].first == p.registerOffset)
                                    return i;
                            return abi.size();
                        };
                        return abiIndex(a) < abiIndex(b);
                    });
                // Return type: unanimous ignoring downgrades integer
                // returns to void (the typed wrapper rewrites the body's
                // machine-return for void); a dereferenced return is a
                // pointer.  Struct/float returns are left untouched - the
                // adapter only rewrites plain integer returns.  Tail
                // dispatchers keep their return: decompileTyped promotes
                // them back to a 64-bit value (the dispatch forwards rax),
                // and a cross-unit void downgrade would conflict with it.
                // The inverse direction upgrades a void callee when callers
                // consume its result: import thunks and tail-jump wrappers
                // recover void from their body alone (a bare jump has no
                // explicit return value), but a caller binding the result
                // is definitive evidence the value exists.  A dereferenced
                // result upgrades straight to a pointer.
                if (kv.second.sites > 0 && kv.second.anyReturnValue &&
                    sig.returnType.kind == TypeKind::VOID_TYPE &&
                    !tailDispatchers.count(kv.first)) {
                    sig.returnType = kv.second.returnDereferenced
                        ? DataType{TypeKind::POINTER, 64, 1}
                        : DataType{TypeKind::UNSIGNED_INT, 64, 1};
                    if (sig.returnComponents.size() == 1)
                        sig.returnComponents[0] = sig.returnType;
                    changed = true;
                } else if (kv.second.sites > 0 && !kv.second.anyReturnValue &&
                    !tailDispatchers.count(kv.first) &&
                    (sig.returnType.kind == TypeKind::UNSIGNED_INT ||
                     sig.returnType.kind == TypeKind::SIGNED_INT ||
                     sig.returnType.kind == TypeKind::BOOL ||
                     sig.returnType.kind == TypeKind::UNKNOWN)) {
                    sig.returnType = {TypeKind::VOID_TYPE, 0, 1};
                    sig.returnValues.clear();
                    sig.returnComponents.clear();
                    changed = true;
                } else if (kv.second.returnDereferenced &&
                           sig.returnType.kind != TypeKind::POINTER &&
                           (sig.returnType.kind == TypeKind::UNSIGNED_INT ||
                            sig.returnType.kind == TypeKind::SIGNED_INT ||
                            sig.returnType.kind == TypeKind::UNKNOWN)) {
                    sig.returnType = DataType{TypeKind::POINTER, 64, 1};
                    if (sig.returnComponents.size() == 1)
                        sig.returnComponents[0] = sig.returnType;
                    changed = true;
                }
            }
            if (!changed) break;
        }
    }
    const auto refinementFinished = std::chrono::steady_clock::now();
    if (std::getenv("CENTRIFUGE_ANALYSIS_PROFILE")) {
        const auto secondsBetween = [](const auto& begin, const auto& end) {
            return std::chrono::duration<double>(end - begin).count();
        };
        std::fprintf(stderr,
            "[analysis-profile] functions=%zu threads=%zu main=%.3fs cfg=%.3fs "
            "ir=%.3fs post=%.3fs modref=%.3fs cpp=%.3fs total=%.3fs\n",
            functions_.size(), analysisWorkers,
            secondsBetween(analysisProfileStarted, mainAnalysisFinished),
            profiledCfgSeconds, profiledIrSeconds, profiledPostSeconds,
            secondsBetween(modRefStarted, modRefFinished),
            secondsBetween(modRefFinished, refinementFinished),
            secondsBetween(analysisProfileStarted, refinementFinished));
        std::fflush(stderr);
    }
    return true;
}

std::string ProgramAnalysis::decompileFunction(const Program& program,
                                               const SleighEngine& engine,
                                               uint64_t address) const {
    const AnalyzedFunction* analyzed = functionAt(address);
    if (!analyzed || !analyzed->complete) return "// function analysis unavailable\n";
    auto read = [&](uint64_t source, void* output, size_t size) {
        return program.memory.read(source, output, size);
    };
    auto nameOf = [&](uint64_t target) {
        const AnalyzedFunction* function = functionAt(target);
        if (function) return function->function.name;
        // Match the analysis naming convention (analysis.cpp funName) so
        // callees outside the function table do not appear in a different
        // FUN_ format from discovered ones.
        const bool is32 =
            architecture_ == "x86" || architecture_ == "arm" ||
            architecture_ == "mips" || architecture_ == "riscv32";
        char buffer[40];
        std::snprintf(buffer, sizeof(buffer),
                      is32 ? "FUN_%08llX" : "FUN_%016llX",
                      static_cast<unsigned long long>(target));
        return std::string(buffer);
    };
    auto signatureOf = [&](uint64_t target) { return signatureAt(target); };
    uint64_t end = 0;
    if (analyzed->function.size && address <=
            std::numeric_limits<uint64_t>::max() - analyzed->function.size)
        end = address + analyzed->function.size;
    std::ostringstream output;
    output << "#include <stdint.h>\n\n";
    std::set<std::string> emittedTypes;
    std::function<void(const DataType&)> emitType;
    emitType = [&](const DataType& type) {
        if (type.kind == TypeKind::POINTER && type.detail &&
            type.detail->elementType) {
            emitType(*type.detail->elementType);
            return;
        }
        if ((type.kind != TypeKind::STRUCT && type.kind != TypeKind::UNION) ||
            !type.detail || !emittedTypes.insert(type.detail->name).second)
            return;
        for (const TypeField& field : type.detail->fields) emitType(field.type);
        output << (type.kind == TypeKind::STRUCT ? "struct " : "union ")
               << type.detail->name << " {\n";
        // Overlapping fields share an offset and therefore a generated
        // name ("field_0"); duplicate member names are invalid C, so
        // disambiguate with a numeric suffix.  The bodies access these
        // objects through raw pointer casts, never by member name, so the
        // rename is display-only.
        std::map<std::string, int> usedNames;
        for (const TypeField& field : type.detail->fields) {
            std::string name = field.name;
            const int seen = usedNames[name]++;
            if (seen > 0) name += "_" + std::to_string(seen + 1);
            output << "    " << field.type.declaration(name) << ";\n";
        }
        output << "};\n\n";
    };
    emitType(analyzed->signature.returnType);
    for (const FunctionParameter& parameter : analyzed->signature.parameters)
        emitType(parameter.type);
    for (uint64_t calleeAddress : analyzed->callees) {
        if (calleeAddress == address) continue;
        const AnalyzedFunction* callee = functionAt(calleeAddress);
        if (callee && callee->complete)
            output << callee->signature.declaration(callee->function.name) << ";\n";
    }
    // WS3: struct layouts recovered for this function's own call results.
    // The emitter names members through explicit casts, which need the
    // complete type visible before the body.
    for (const auto& kv : analyzed->callResultTypes) emitType(kv.second);
    if (!analyzed->callees.empty()) output << "\n";
    // WS3: member accessors for pointer parameters whose recovered type
    // carries a struct layout.  The emitter rewrites entry-block
    // *(T *)(paramK + K) accesses to paramK->member.  Member names must
    // match the (possibly suffixed) names emitType prints, so replicate
    // its per-name deduplication counting.
    FieldAccessorMap fieldAccessors;
    for (const FunctionParameter& parameter : analyzed->signature.parameters) {
        if (parameter.onStack ||
            parameter.type.kind != TypeKind::POINTER ||
            !parameter.type.detail ||
            !parameter.type.detail->elementType ||
            parameter.type.detail->elementType->kind != TypeKind::STRUCT)
            continue;
        std::map<std::string, int> usedNames;
        for (const TypeField& field : parameter.type.detail->elementType->detail->fields) {
            std::string name = field.name;
            const int seen = usedNames[name]++;
            if (seen > 0) name += "_" + std::to_string(seen + 1);
            fieldAccessors[{parameter.registerOffset,
                            static_cast<int64_t>(field.byteOffset)}] = {
                name, field.type.bits};
        }
    }
    output << decompileTyped(engine, read, address, end, architecture_,
                             analyzed->function.name, analyzed->signature,
                             nameOf, signatureOf, false, nullptr, nullptr,
                             nullptr,
                             fieldAccessors.empty() ? nullptr
                                                    : &fieldAccessors,
                             analyzed->callResultTypes.empty()
                                 ? nullptr
                                 : &analyzed->callResultTypes);
    return output.str();
}

} // namespace centrifuge
