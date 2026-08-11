// centrifuge - whole-program recovery knowledge graph
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "centrifuge/cpp_recovery.hpp"
#include "centrifuge/loader.hpp"

namespace centrifuge {

class ProgramAnalysis;

enum class KnowledgeNodeKind {
    BINARY, MODULE, FUNCTION, CLASS_TYPE, DATA_TYPE, PARAMETER, FIELD,
    OBJECT, VTABLE, GLOBAL, DATA_REGION, IMPORT_LIBRARY, IMPORT_SYMBOL,
    RESOURCE, ENTRY_POINT, CALL_SITE, RUNTIME_OPERATION,
};

enum class KnowledgeEdgeKind {
    CONTAINS, CALLS, OWNS, INHERITS, HAS_TYPE, READS, WRITES, ALIASES,
    CONSTRUCTS, DESTROYS, ALLOCATES, DEALLOCATES, INITIALIZES_VPTR,
    RESOLVES_TO, RETURNS_TYPE, EVIDENCE_FOR, IMPORTS, ENTERS_AT,
};

struct KnowledgeNode {
    uint64_t id = 0;
    KnowledgeNodeKind kind = KnowledgeNodeKind::FUNCTION;
    std::string key;
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    double confidence = 0;
    std::vector<CppEvidence> evidence;
};

struct KnowledgeEdge {
    uint64_t id = 0;
    uint64_t from = 0;
    uint64_t to = 0;
    KnowledgeEdgeKind kind = KnowledgeEdgeKind::CONTAINS;
    double confidence = 0;
    std::string reason;
};

class ProgramKnowledgeGraph {
public:
    uint64_t addNode(KnowledgeNodeKind kind, const std::string& key,
                     const std::string& name = {}, uint64_t address = 0,
                     uint64_t size = 0, double confidence = 0);
    uint64_t addEdge(uint64_t from, uint64_t to, KnowledgeEdgeKind kind,
                     double confidence, const std::string& reason = {});
    KnowledgeNode* node(uint64_t id);
    const KnowledgeNode* node(uint64_t id) const;
    std::optional<uint64_t> find(const std::string& key) const;
    const std::vector<KnowledgeNode>& nodes() const { return nodes_; }
    const std::vector<KnowledgeEdge>& edges() const { return edges_; }
    std::string toJson() const;

private:
    uint64_t nextNode_ = 1;
    uint64_t nextEdge_ = 1;
    std::vector<KnowledgeNode> nodes_;
    std::vector<KnowledgeEdge> edges_;
    std::map<std::string, uint64_t> keys_;
};

ProgramKnowledgeGraph buildProgramKnowledgeGraph(
    const Program& program, const ProgramAnalysis& analysis);

const char* knowledgeNodeKindName(KnowledgeNodeKind kind);
const char* knowledgeEdgeKindName(KnowledgeEdgeKind kind);

} // namespace centrifuge
