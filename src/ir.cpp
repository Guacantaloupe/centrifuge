// centrifuge - function-level SSA, type, ABI, optimization, and jump tables
#include "centrifuge/ir.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <tuple>

namespace centrifuge {
namespace {

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
    case POp::STORE: case POp::SELECT: return 3;
    case POp::RETURN: return 0;
    default: return 2;
    }
}

bool pure(POp op) {
    return op != POp::STORE && op != POp::BRANCH && op != POp::CBRANCH &&
           op != POp::BRANCHIND && op != POp::CALL && op != POp::CALLIND &&
           op != POp::RETURN && op != POp::LOAD;
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
    if (a.kind == TypeKind::POINTER || b.kind == TypeKind::POINTER)
        return {TypeKind::POINTER, std::max(a.bits, b.bits), 1};
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

} // namespace

std::string DataType::name() const {
    switch (kind) {
    case TypeKind::BOOL: return "bool";
    case TypeKind::POINTER: return "void *";
    case TypeKind::FLOAT: return bits <= 32 ? "float" : "double";
    case TypeKind::VECTOR:
        return "vector" + std::to_string(bits) + "x" + std::to_string(lanes);
    case TypeKind::SIGNED_INT: return "int" + std::to_string(bits) + "_t";
    case TypeKind::UNSIGNED_INT: return "uint" + std::to_string(bits) + "_t";
    case TypeKind::MEMORY: return "memory";
    case TypeKind::VOID_TYPE: return "void";
    case TypeKind::UNKNOWN: return bits ? "uint" + std::to_string(bits) + "_t"
                                         : "uint64_t";
    }
    return "uint64_t";
}

std::string FunctionSignature::declaration(const std::string& name) const {
    std::string out = returnType.name() + " " + name + "(";
    if (parameters.empty() && !variadic) out += "void";
    for (size_t i = 0; i < parameters.size(); ++i) {
        if (i) out += ", ";
        out += parameters[i].type.name() + " " + parameters[i].name;
    }
    if (variadic) out += parameters.empty() ? "..." : ", ...";
    return out + ")";
}

const SsaValue* FunctionIR::value(SsaId id) const {
    const auto it = values_.find(id);
    return it == values_.end() ? nullptr : &it->second;
}

bool FunctionIR::build(const CfgBuilder& cfg, const std::string& architecture,
                       const std::string& callingConvention) {
    arch_ = architecture;
    callingConvention_ = callingConvention;
    blocks_.clear(); blockIndex_.clear(); values_.clear(); outgoing_.clear();
    parameters_.clear(); nextId_ = 1;
    if (cfg.blocks().empty()) return false;

    std::set<RegKey> registers;
    for (const auto& block : cfg.blocks())
        for (const auto& insn : block.insns)
            for (const auto& kv : insn.varnodes) {
                const Varnode& v = kv.second;
                if (v.kind == Varnode::REGISTER)
                    registers.emplace(v.offset, v.size);
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
                if (op.op == POp::STORE) {
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
                const auto def = definitions.find({block.start, insn.addr, oi});
                if (def != definitions.end()) {
                    so.output = def->second.id;
                    const Varnode* node = insn.find(op.out);
                    if (node) local[op.out] = so.output;
                    if (def->second.key == memoryKey ||
                        values_.at(so.output).storage == SsaValue::REGISTER)
                        state[def->second.key] = so.output;
                }
                sb.ops.push_back(std::move(so));
            }
        }
    }
    inferTypes();
    return true;
}

void FunctionIR::inferTypes() {
    auto constrain = [&](SsaId id, DataType wanted) {
        auto it = values_.find(id);
        if (it == values_.end()) return false;
        const DataType merged = mergeType(it->second.type, wanted);
        if (merged == it->second.type) return false;
        it->second.type = merged; return true;
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
            }
            for (const SsaOp& op : block.ops) {
                const SsaValue* out = value(op.output);
                const int bits = out && out->size ? out->size * 8 : 64;
                switch (op.op) {
                case POp::CBRANCH:
                    if (op.inputs.size() > 1) changed |= constrain(op.inputs[1], {TypeKind::BOOL, 1, 1});
                    break;
                case POp::LOAD:
                    if (!op.inputs.empty()) changed |= constrain(op.inputs[0], {TypeKind::POINTER, 64, 1});
                    changed |= constrain(op.output, {TypeKind::UNSIGNED_INT, bits, 1});
                    break;
                case POp::STORE:
                    if (!op.inputs.empty()) changed |= constrain(op.inputs[0], {TypeKind::POINTER, 64, 1});
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
                default:
                    if (op.output) changed |= constrain(op.output, {TypeKind::UNSIGNED_INT, bits, 1});
                    break;
                }
            }
        }
    }
}

FunctionSignature FunctionIR::inferSignature() const {
    FunctionSignature sig;
    std::vector<std::pair<uint64_t, std::string>> abiArgs;
    uint64_t returnReg = 0;
    if (arch_.rfind("x86", 0) == 0) {
        if (callingConvention_ == "win64" || callingConvention_ == "ms")
            abiArgs = {{1 * 8, "arg0"}, {2 * 8, "arg1"},
                       {8 * 8, "arg2"}, {9 * 8, "arg3"}};
        else
            abiArgs = {{7 * 8, "arg0"}, {6 * 8, "arg1"}, {2 * 8, "arg2"},
                       {1 * 8, "arg3"}, {8 * 8, "arg4"}, {9 * 8, "arg5"}};
        returnReg = 0;
    } else if (arch_.rfind("riscv", 0) == 0) {
        for (int i = 0; i < 8; ++i) abiArgs.emplace_back((10 + i) * 8, "arg" + std::to_string(i));
        returnReg = 10 * 8;
    } else if (arch_ == "aarch64" || arch_ == "arm64") {
        for (int i = 0; i < 8; ++i) abiArgs.emplace_back(i * 8, "arg" + std::to_string(i));
        returnReg = 0;
    } else {
        abiArgs = {{0, "arg0"}, {8, "arg1"}, {16, "arg2"}, {24, "arg3"}};
        returnReg = 0;
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
        for (const auto& param : parameters_) {
            if (param.first.first != arg.first || !used.count(param.second)) continue;
            const SsaValue& v = values_.at(param.second);
            sig.parameters.push_back({arg.second, arg.first, param.second,
                                      v.type.kind == TypeKind::UNKNOWN
                                          ? DataType{TypeKind::UNSIGNED_INT, v.size * 8, 1}
                                          : v.type});
            break;
        }
    }

    for (const SsaBlock& block : blocks_) {
        bool returns = false;
        for (const SsaOp& op : block.ops) if (op.op == POp::RETURN) returns = true;
        if (!returns) continue;
        for (const auto& state : outgoing_) {
            if (state.first != block.start) continue;
            for (const auto& reg : state.second) {
                if (reg.first.first != returnReg) continue;
                const SsaValue& v = values_.at(reg.second);
                if (v.version == 0) continue;
                sig.returnValues.push_back(v.id);
                sig.returnType = mergeType(sig.returnType.kind == TypeKind::VOID_TYPE
                                               ? DataType{} : sig.returnType,
                                           v.type);
            }
        }
    }
    if (!sig.returnValues.empty() && sig.returnType.kind == TypeKind::UNKNOWN)
        sig.returnType = {TypeKind::UNSIGNED_INT, 64, 1};
    return sig;
}

void FunctionIR::optimize() {
    std::map<SsaId, SsaId> replace;
    auto canonical = [&](SsaId id) {
        while (replace.count(id)) id = replace[id];
        return id;
    };
    std::map<std::tuple<POp, SsaId, SsaId>, SsaId> expressions;
    for (SsaBlock& block : blocks_) {
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

size_t FunctionIR::phiCount() const {
    size_t n = 0; for (const auto& b : blocks_) n += b.phis.size(); return n;
}
size_t FunctionIR::liveOpCount() const {
    size_t n = 0; for (const auto& b : blocks_) for (const auto& op : b.ops) n += !op.removed; return n;
}

std::string FunctionIR::dump() const {
    std::ostringstream out;
    for (const auto& block : blocks_) {
        out << "block 0x" << std::hex << block.start << std::dec << ":\n";
        auto print = [&](const SsaOp& op) {
            if (op.removed) return;
            if (op.output) out << "  v" << op.output << " = "; else out << "  ";
            out << (op.phi ? "PHI" : pOpName(op.op)) << "(";
            for (size_t i = 0; i < op.inputs.size(); ++i) {
                if (i) out << ", ";
                out << "v" << op.inputs[i];
            }
            out << ")\n";
        };
        for (const auto& op : block.phis) print(op);
        for (const auto& op : block.ops) print(op);
    }
    return out.str();
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

} // namespace centrifuge
