// centrifuge - structured HighIR / AST recovered from a control-flow graph
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/ir.hpp"

namespace centrifuge {

enum class HighNodeKind {
    SEQUENCE,
    BASIC_BLOCK,
    IF,
    IF_ELSE,
    WHILE_LOOP,
    DO_WHILE_LOOP,
    INFINITE_LOOP,
    SWITCH,
    CASE,
    RETURN_NODE,
    IRREDUCIBLE_REGION,
    GOTO_NODE,
};

struct HighNode {
    HighNodeKind kind = HighNodeKind::BASIC_BLOCK;
    uint64_t address = 0;
    std::string label;
    std::set<uint64_t> coveredBlocks;
    std::vector<uint64_t> targets;
    std::vector<std::unique_ptr<HighNode>> children;
};

struct HighFunction {
    std::unique_ptr<HighNode> root;
    std::vector<std::set<uint64_t>> irreducibleRegions;
    size_t structuredNodes = 0;
    std::string dump() const;
};

class HighIRBuilder {
public:
    HighFunction build(const CfgBuilder& cfg,
                       const std::vector<JumpTable>& jumpTables = {}) const;
};

} // namespace centrifuge
