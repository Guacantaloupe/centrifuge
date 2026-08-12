// centrifuge - calling-convention recovery implementation.
#include "centrifuge/calling_convention.hpp"

#include <algorithm>
#include <functional>
#include <set>

namespace centrifuge {

namespace {

// Resolve a p-code varnode id back to its varnode within an instruction.
const Varnode* findNode(const PcodeInsn& insn, uint64_t id) {
    return id ? insn.find(id) : nullptr;
}

// True if the value at `id` (a LOAD/STORE address) is a stack access whose
// displacement contains a dynamic register term (rsp + reg*8 + K).  `spReg`
// is the architectural stack pointer register offset; `bpReg` the frame
// pointer offset (0 if none).  The tree must reach the stack pointer AND
// contain some dynamic (non-sp, non-frame) register term.
bool hasIndexedDisplacement(const PcodeInsn& insn, uint64_t id,
                            uint64_t spReg, uint64_t bpReg) {
    std::function<bool(uint64_t, std::set<uint64_t>&, bool&, bool&)>
        indexed;
    indexed = [&](uint64_t valueId, std::set<uint64_t>& visiting,
                  bool& reachesStack, bool& dynamic) -> bool {
        if (!valueId || !visiting.insert(valueId).second)
            return reachesStack && dynamic;
        const Varnode* node = findNode(insn, valueId);
        if (!node) return reachesStack && dynamic;
        if (node->kind == Varnode::CONST) return reachesStack && dynamic;
        if (node->kind == Varnode::REGISTER) {
            if (node->offset == spReg || node->offset == bpReg)
                reachesStack = true;
            else
                dynamic = true;
            return reachesStack && dynamic;
        }
        // UNIQUE: expand its defining op.
        for (const PcodeOp& op : insn.ops) {
            if (op.out != valueId) continue;
            if (op.op == POp::COPY)
                return indexed(op.in0, visiting, reachesStack, dynamic);
            if (op.op == POp::INT_ADD || op.op == POp::INT_SUB ||
                op.op == POp::INT_MULT || op.op == POp::INT_LEFT) {
                bool leftStack = reachesStack, leftDynamic = dynamic;
                bool rightStack = reachesStack, rightDynamic = dynamic;
                std::set<uint64_t> left = visiting, right = visiting;
                const bool a = indexed(op.in0, left, leftStack, leftDynamic);
                const bool b = indexed(op.in1, right, rightStack, rightDynamic);
                reachesStack = leftStack || rightStack;
                dynamic = leftDynamic || rightDynamic;
                return a || b || (reachesStack && dynamic);
            }
            if (op.op == POp::INT_ZEXT || op.op == POp::INT_SEXT)
                return indexed(op.in0, visiting, reachesStack, dynamic);
            dynamic = true; // unknown producer
            return reachesStack && dynamic;
        }
        return reachesStack && dynamic;
    };
    std::set<uint64_t> visiting;
    bool reachesStack = false, dynamic = false;
    return indexed(id, visiting, reachesStack, dynamic);
}

} // namespace

CallConventionFacts recoverCallConvention(const FunctionIR& ir,
                                          const CfgBuilder& cfg,
                                          const std::string& architecture) {
    CallConventionFacts facts;

    const bool x86 = architecture.rfind("x86", 0) == 0;
    const bool win64 = architecture.find("win64") != std::string::npos ||
                       architecture.find("ms") != std::string::npos;
    const uint64_t spReg = x86 ? (architecture == "x86" ? 4 * 8 : 4 * 8)
                               : (architecture.rfind("riscv", 0) == 0 ? 2 * 8
                                  : (architecture == "aarch64" ||
                                     architecture == "arm64") ? 31 * 8 : 0);
    const uint64_t bpReg = x86 ? (architecture == "x86" ? 5 * 4 : 5 * 8) : 0;
    const int64_t firstStackArgument = win64 ? 40 : (x86 ? 8 : 0);

    // --- stack arguments ------------------------------------------------
    for (const auto& entry : ir.stackInputs()) {
        if (entry.first < firstStackArgument) continue;
        const SsaValue* value = ir.value(entry.second);
        facts.readsStackArguments = true;
        facts.stackSlots.emplace_back(entry.first,
                                      value ? value->size : 8);
    }
    std::sort(facts.stackSlots.begin(), facts.stackSlots.end());

    // --- indexed stack access (variadic hint) ----------------------------
    for (const CfgBlock& block : cfg.blocks()) {
        for (const PcodeInsn& insn : block.insns) {
            for (const PcodeOp& op : insn.ops) {
                if (op.op != POp::LOAD && op.op != POp::STORE) continue;
                if (hasIndexedDisplacement(insn, op.in0, spReg, bpReg))
                    facts.indexedStackAccess = true;
            }
        }
    }

    // --- sret hints: return value == first integer arg, stores through it --
    // Win64: first integer argument register is RCX (offset 8).  SystemV:
    // RDI (offset 56).  Match any size view of the same register.
    const uint64_t firstArgReg = win64 ? 1 * 8 : (x86 ? 7 * 8 : 10 * 8);
    SsaId firstArgValue = 0;
    for (const auto& parameter : ir.parameters()) {
        if (parameter.first.first != firstArgReg) continue;
        // Prefer the widest view (RCX over ECX/CX).
        if (!firstArgValue ||
            parameter.first.second >
                ir.value(firstArgValue)->size)
            firstArgValue = parameter.second;
    }
    size_t liveInArguments = 0;
    const auto abiArgs = abiArguments(architecture, win64 ? "win64" : "");
    for (const auto& argument : abiArgs) {
        bool live = false;
        for (const auto& parameter : ir.parameters()) {
            if (parameter.first.first != argument.first) continue;
            live = true;
            break;
        }
        if (live) ++liveInArguments;
    }
    facts.fixedRegisterArguments = liveInArguments;

    // Follow COPY/zero-extension def chains so `mov rax, rcx; ret` counts as
    // returning the first argument even though RAX gets a fresh SSA id.
    std::map<SsaId, SsaId> copyTargets;
    for (const SsaBlock& block : ir.blocks())
        for (const SsaOp& op : block.ops)
            if ((op.op == POp::COPY || op.op == POp::INT_ZEXT ||
                 op.op == POp::INT_SEXT) &&
                op.output && !op.inputs.empty())
                copyTargets.emplace(op.output, op.inputs[0]);
    std::function<bool(SsaId)> derivesFromFirstArg;
    std::set<SsaId> chainVisiting;
    derivesFromFirstArg = [&](SsaId id) -> bool {
        if (!id) return false;
        if (id == firstArgValue) return true;
        if (!chainVisiting.insert(id).second) return false;
        const auto next = copyTargets.find(id);
        const bool result = next != copyTargets.end() &&
                            derivesFromFirstArg(next->second);
        chainVisiting.erase(id);
        return result;
    };

    for (const SsaBlock& block : ir.blocks()) {
        for (const SsaOp& op : block.ops) {
            if (op.op == POp::STORE && firstArgValue &&
                !op.inputs.empty() &&
                derivesFromFirstArg(op.inputs[0]))
                facts.writesThroughFirstArg = true;
        }
        // The x86 `ret` p-code has no explicit return operand; the return
        // value is the RAX state at the RETURN block's exit.
        bool returns = false;
        for (const SsaOp& op : block.ops)
            if (op.op == POp::RETURN) returns = true;
        if (!returns) continue;
        const auto exit = ir.outgoing().find(block.start);
        if (exit == ir.outgoing().end()) continue;
        for (const auto& reg : exit->second) {
            if (reg.first.first != 0) continue; // RAX/EAX/AX/AL views
            if (derivesFromFirstArg(reg.second))
                facts.returnsPointerArgument = true;
        }
    }

    // --- verdicts --------------------------------------------------------
    // A variadic callee walks its own stack arguments through a dynamic
    // index; a fixed-arity callee only ever reads constant offsets.  The
    // indexed access must reach the stack pointer, so plain array
    // addressing through a frame base does not trip the heuristic.
    facts.variadic = facts.indexedStackAccess;
    // sret: the function stores into the buffer pointed to by its first
    // argument *and* returns that pointer.  Thunks that merely forward RCX
    // (return-only) are deliberately excluded.
    facts.hiddenSret = facts.returnsPointerArgument &&
                       facts.writesThroughFirstArg;
    return facts;
}

void applyCallConvention(const CallConventionFacts& facts,
                         FunctionSignature& signature,
                         const std::string& architecture) {
    const bool win64 = architecture.find("win64") != std::string::npos ||
                       architecture.find("ms") != std::string::npos;
    signature.variadic = signature.variadic || facts.variadic;

    if (!facts.hiddenSret || signature.parameters.empty()) return;
    // Mark the first parameter as the hidden return buffer.  Keep the type
    // as a pointer so native output can emit the declaration; struct-shape
    // recovery (TypeRecovery) will refine it later.
    FunctionParameter& first = signature.parameters.front();
    if (first.registerOffset != (win64 ? 1 * 8 : 7 * 8)) return;
    first.name = "ret";
    first.type = DataType{TypeKind::POINTER, 64, 1};
    signature.hiddenSret = true;
    // The machine function physically returns the buffer pointer in RAX;
    // that is the sret convention, not a meaningful scalar return value.
    // Even when type propagation inferred POINTER from the address use,
    // the recovered signature must present the logical (void) return.
    signature.returnType = {TypeKind::VOID_TYPE, 0, 1};
    signature.returnValues.clear();
    signature.returnComponents.clear();
}

} // namespace centrifuge
