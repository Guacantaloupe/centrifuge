// centrifuge - global object recovery implementation.
#include "centrifuge/global_recovery.hpp"

#include <algorithm>
#include <functional>
#include <set>

namespace centrifuge {

namespace {

// Resolve a LOAD/STORE address varnode to a constant when the whole address
// tree is constant (CONST, COPY-of-CONST, INT_ADD/SUB of constants).
bool resolveConstAddress(const PcodeInsn& insn, uint64_t id,
                         uint64_t& result) {
    std::function<bool(uint64_t, std::set<uint64_t>&, uint64_t&)> resolve;
    resolve = [&](uint64_t valueId, std::set<uint64_t>& visiting,
                  uint64_t& out) -> bool {
        if (!valueId || !visiting.insert(valueId).second) return false;
        const Varnode* node = insn.find(valueId);
        if (!node) return false;
        if (node->kind == Varnode::CONST) {
            out = node->offset;
            return true;
        }
        if (node->kind != Varnode::UNIQUE) return false;
        for (const PcodeOp& op : insn.ops) {
            if (op.out != valueId) continue;
            if (op.op == POp::COPY)
                return resolve(op.in0, visiting, out);
            if (op.op != POp::INT_ADD && op.op != POp::INT_SUB)
                return false;
            uint64_t left = 0, right = 0;
            std::set<uint64_t> nested = visiting;
            if (!resolve(op.in0, nested, left)) return false;
            if (!resolve(op.in1, visiting, right)) return false;
            out = op.op == POp::INT_SUB ? left - right : left + right;
            return true;
        }
        return false;
    };
    std::set<uint64_t> visiting;
    return resolve(id, visiting, result);
}

} // namespace

void GlobalObjectRecovery::analyze(
    const CfgBuilder& cfg, const MemoryImage& memory,
    const std::function<std::string(uint64_t)>& symbolName) {
    objects_.clear();
    byAddress_.clear();
    std::map<uint64_t, GlobalField> accesses;
    for (const CfgBlock& block : cfg.blocks()) {
        for (const PcodeInsn& insn : block.insns) {
            for (const PcodeOp& op : insn.ops) {
                if (op.op != POp::LOAD && op.op != POp::STORE) continue;
                uint64_t address = 0;
                if (!resolveConstAddress(insn, op.in0, address)) continue;
                // Only data-segment (non-executable) targets are globals.
                if (memory.isExecutable(address)) continue;
                const Varnode* value = insn.find(op.out);
                const int width =
                    op.op == POp::LOAD && value ? value->size : 0;
                GlobalField& field = accesses[address];
                field.byteOffset = 0; // per-object, patched below
                if (width > field.widthBytes) field.widthBytes = width;
                if (op.op == POp::STORE) field.written = true;
            }
        }
    }
    if (accesses.empty()) return;
    // Cluster accesses into objects: merge any two addresses whose span is
    // <= 16 bytes (typical small globals) into one object.
    std::vector<std::pair<uint64_t, GlobalField>> sorted(accesses.begin(),
                                                         accesses.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    uint64_t objectStart = sorted.front().first;
    uint64_t objectEnd = objectStart + sorted.front().second.widthBytes;
    std::vector<std::pair<uint64_t, GlobalField>> current{
        sorted.front()};
    auto flush = [&]() {
        GlobalObject object;
        object.address = objectStart;
        object.size = objectEnd - objectStart;
        for (const auto& access : current) {
            GlobalField field = access.second;
            field.byteOffset = access.first - objectStart;
            object.fields.push_back(field);
        }
        std::sort(object.fields.begin(), object.fields.end(),
                  [](const GlobalField& a, const GlobalField& b) {
                      return a.byteOffset < b.byteOffset;
                  });
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "g_data_%llx",
                      static_cast<unsigned long long>(objectStart));
        object.name = buffer;
        if (symbolName) {
            const std::string known = symbolName(objectStart);
            if (!known.empty()) object.name = known;
        }
        byAddress_[object.address] = objects_.size();
        objects_.push_back(std::move(object));
    };
    for (size_t index = 1; index < sorted.size(); ++index) {
        const auto& access = sorted[index];
        const uint64_t span = access.first + access.second.widthBytes;
        if (access.first <= objectEnd + 16) {
            objectEnd = std::max(objectEnd, span);
            current.push_back(access);
            continue;
        }
        flush();
        objectStart = access.first;
        objectEnd = span;
        current.clear();
        current.push_back(access);
    }
    flush();
}

const GlobalObject* GlobalObjectRecovery::objectAt(uint64_t address) const {
    const auto found = byAddress_.find(address);
    if (found == byAddress_.end()) return nullptr;
    return &objects_[found->second];
}

} // namespace centrifuge
