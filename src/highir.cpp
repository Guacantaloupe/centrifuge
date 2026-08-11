// centrifuge - CFG to structured HighIR / AST recovery
#include "centrifuge/highir.hpp"

#include <algorithm>
#include <functional>
#include <sstream>

namespace centrifuge {
namespace {

const char* highNodeName(HighNodeKind kind) {
    switch (kind) {
    case HighNodeKind::SEQUENCE: return "sequence";
    case HighNodeKind::BASIC_BLOCK: return "block";
    case HighNodeKind::IF: return "if";
    case HighNodeKind::IF_ELSE: return "if_else";
    case HighNodeKind::WHILE_LOOP: return "while";
    case HighNodeKind::DO_WHILE_LOOP: return "do_while";
    case HighNodeKind::INFINITE_LOOP: return "infinite_loop";
    case HighNodeKind::SWITCH: return "switch";
    case HighNodeKind::CASE: return "case";
    case HighNodeKind::RETURN_NODE: return "return";
    case HighNodeKind::IRREDUCIBLE_REGION: return "irreducible";
    case HighNodeKind::GOTO_NODE: return "goto";
    }
    return "node";
}

void dumpNode(const HighNode& node, std::ostringstream& output, int depth) {
    output << std::string(static_cast<size_t>(depth) * 2, ' ')
           << highNodeName(node.kind) << " 0x" << std::hex << node.address
           << std::dec;
    if (!node.label.empty()) output << " " << node.label;
    if (!node.targets.empty()) {
        output << " ->";
        for (uint64_t target : node.targets)
            output << " 0x" << std::hex << target << std::dec;
    }
    output << "\n";
    for (const auto& child : node.children) dumpNode(*child, output, depth + 1);
}

} // namespace

std::string HighFunction::dump() const {
    std::ostringstream output;
    if (root) dumpNode(*root, output, 0);
    return output.str();
}

HighFunction HighIRBuilder::build(
    const CfgBuilder& cfg, const std::vector<JumpTable>& jumpTables) const {
    HighFunction result;
    result.root = std::make_unique<HighNode>();
    result.root->kind = HighNodeKind::SEQUENCE;
    if (cfg.blocks().empty()) return result;
    result.root->address = cfg.blocks().front().start;

    std::map<uint64_t, const CfgBlock*> blocks;
    for (const CfgBlock& block : cfg.blocks()) blocks[block.start] = &block;

    // Tarjan SCCs identify irreducible regions: a cyclic SCC with more than
    // one entry edge cannot be represented by a single natural-loop header.
    std::map<uint64_t, int> index, low;
    std::vector<uint64_t> stack;
    std::set<uint64_t> onStack;
    int nextIndex = 0;
    std::vector<std::set<uint64_t>> components;
    std::function<void(uint64_t)> visit = [&](uint64_t address) {
        index[address] = low[address] = nextIndex++;
        stack.push_back(address);
        onStack.insert(address);
        for (uint64_t successor : blocks[address]->succs) {
            if (!blocks.count(successor)) continue;
            if (!index.count(successor)) {
                visit(successor);
                low[address] = std::min(low[address], low[successor]);
            } else if (onStack.count(successor)) {
                low[address] = std::min(low[address], index[successor]);
            }
        }
        if (low[address] != index[address]) return;
        std::set<uint64_t> component;
        for (;;) {
            const uint64_t member = stack.back();
            stack.pop_back();
            onStack.erase(member);
            component.insert(member);
            if (member == address) break;
        }
        components.push_back(std::move(component));
    };
    for (const auto& block : blocks)
        if (!index.count(block.first)) visit(block.first);

    std::set<uint64_t> claimed;
    for (const std::set<uint64_t>& component : components) {
        bool cyclic = component.size() > 1;
        if (!cyclic && !component.empty()) {
            const CfgBlock* block = blocks[*component.begin()];
            cyclic = std::find(block->succs.begin(), block->succs.end(),
                               block->start) != block->succs.end();
        }
        if (!cyclic) continue;
        std::set<uint64_t> entries;
        for (uint64_t member : component)
            for (uint64_t predecessor : cfg.predecessors(member))
                if (!component.count(predecessor)) entries.insert(member);
        if (entries.size() <= 1) continue;
        result.irreducibleRegions.push_back(component);
        auto node = std::make_unique<HighNode>();
        node->kind = HighNodeKind::IRREDUCIBLE_REGION;
        node->address = *component.begin();
        node->coveredBlocks = component;
        node->label = "multi-entry SCC";
        for (uint64_t member : component) {
            auto child = std::make_unique<HighNode>();
            child->kind = HighNodeKind::GOTO_NODE;
            child->address = member;
            child->targets = blocks[member]->succs;
            node->children.push_back(std::move(child));
        }
        claimed.insert(component.begin(), component.end());
        result.root->children.push_back(std::move(node));
    }

    std::map<uint64_t, const JumpTable*> tables;
    for (const JumpTable& table : jumpTables) tables[table.dispatchAddress] = &table;
    for (const auto& tableEntry : tables) {
        auto node = std::make_unique<HighNode>();
        node->kind = HighNodeKind::SWITCH;
        node->address = tableEntry.first;
        node->targets = tableEntry.second->targets;
        node->coveredBlocks.insert(tableEntry.first);
        for (size_t i = 0; i < tableEntry.second->targets.size(); ++i) {
            auto caseNode = std::make_unique<HighNode>();
            caseNode->kind = HighNodeKind::CASE;
            caseNode->address = tableEntry.second->targets[i];
            caseNode->label = "case " + std::to_string(i);
            node->children.push_back(std::move(caseNode));
        }
        claimed.insert(tableEntry.first);
        result.root->children.push_back(std::move(node));
    }

    for (const NaturalLoop& loop : cfg.loops()) {
        if (claimed.count(loop.header)) continue;
        auto node = std::make_unique<HighNode>();
        node->address = loop.header;
        node->coveredBlocks = loop.blocks;
        const CfgBlock* header = cfg.blockAt(loop.header);
        bool conditionalHeader = header && header->isCondBranch();
        bool conditionalTail = false;
        for (const auto& backEdge : loop.backEdges) {
            const CfgBlock* tail = cfg.blockAt(backEdge.first);
            conditionalTail |= tail && tail->isCondBranch();
        }
        node->kind = conditionalHeader ? HighNodeKind::WHILE_LOOP
                     : conditionalTail ? HighNodeKind::DO_WHILE_LOOP
                                       : HighNodeKind::INFINITE_LOOP;
        node->targets.reserve(loop.exits.size());
        for (const auto& exit : loop.exits) node->targets.push_back(exit.second);
        for (uint64_t member : loop.blocks) {
            auto child = std::make_unique<HighNode>();
            child->kind = HighNodeKind::BASIC_BLOCK;
            child->address = member;
            child->coveredBlocks.insert(member);
            node->children.push_back(std::move(child));
        }
        claimed.insert(loop.blocks.begin(), loop.blocks.end());
        result.root->children.push_back(std::move(node));
    }

    for (const CfgBlock& block : cfg.blocks()) {
        if (claimed.count(block.start)) continue;
        auto node = std::make_unique<HighNode>();
        node->address = block.start;
        node->coveredBlocks.insert(block.start);
        if (block.isRet()) {
            node->kind = HighNodeKind::RETURN_NODE;
        } else if (block.isCondBranch() && block.succs.size() == 2) {
            const CfgBlock* left = cfg.blockAt(block.succs[0]);
            const CfgBlock* right = cfg.blockAt(block.succs[1]);
            bool commonJoin = false;
            if (left && right)
                for (uint64_t l : left->succs)
                    commonJoin |= std::find(right->succs.begin(), right->succs.end(),
                                            l) != right->succs.end();
            node->kind = commonJoin ? HighNodeKind::IF_ELSE : HighNodeKind::IF;
            node->targets = block.succs;
        } else {
            node->kind = HighNodeKind::BASIC_BLOCK;
            node->targets = block.succs;
        }
        result.root->children.push_back(std::move(node));
    }

    std::sort(result.root->children.begin(), result.root->children.end(),
              [](const std::unique_ptr<HighNode>& left,
                 const std::unique_ptr<HighNode>& right) {
                  return left->address < right->address;
              });
    result.structuredNodes = result.root->children.size();
    return result;
}

} // namespace centrifuge
