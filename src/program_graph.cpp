// centrifuge - whole-program recovery knowledge graph
#include "centrifuge/program_graph.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <tuple>

#include "centrifuge/ir.hpp"
#include "centrifuge/import_prototype.hpp"

namespace centrifuge {
namespace {

std::string addressKey(uint64_t address) {
    std::ostringstream output;
    output << std::hex << address;
    return output.str();
}

std::string jsonEscape(const std::string& value) {
    std::string output;
    output.reserve(value.size() + 8);
    for (unsigned char character : value) {
        switch (character) {
        case '\\': output += "\\\\"; break;
        case '"': output += "\\\""; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (character < 0x20) {
                char escaped[7];
                std::snprintf(escaped, sizeof(escaped), "\\u%04x", character);
                output += escaped;
            } else {
                output += static_cast<char>(character);
            }
        }
    }
    return output;
}

std::string typeKey(const DataType& type) {
    std::string key = type.name() + ":" + std::to_string(type.bits) + ":" +
                      std::to_string(type.lanes);
    if (type.detail && !type.detail->name.empty()) key += ":" + type.detail->name;
    return key;
}

} // namespace

const char* knowledgeNodeKindName(KnowledgeNodeKind kind) {
    switch (kind) {
    case KnowledgeNodeKind::BINARY: return "binary";
    case KnowledgeNodeKind::MODULE: return "module";
    case KnowledgeNodeKind::FUNCTION: return "function";
    case KnowledgeNodeKind::CLASS_TYPE: return "class";
    case KnowledgeNodeKind::DATA_TYPE: return "type";
    case KnowledgeNodeKind::PARAMETER: return "parameter";
    case KnowledgeNodeKind::FIELD: return "field";
    case KnowledgeNodeKind::OBJECT: return "object";
    case KnowledgeNodeKind::VTABLE: return "vtable";
    case KnowledgeNodeKind::GLOBAL: return "global";
    case KnowledgeNodeKind::DATA_REGION: return "data-region";
    case KnowledgeNodeKind::IMPORT_LIBRARY: return "import-library";
    case KnowledgeNodeKind::IMPORT_SYMBOL: return "import-symbol";
    case KnowledgeNodeKind::RESOURCE: return "resource";
    case KnowledgeNodeKind::ENTRY_POINT: return "entry-point";
    case KnowledgeNodeKind::CALL_SITE: return "call-site";
    case KnowledgeNodeKind::RUNTIME_OPERATION: return "runtime-operation";
    }
    return "unknown";
}

const char* knowledgeEdgeKindName(KnowledgeEdgeKind kind) {
    switch (kind) {
    case KnowledgeEdgeKind::CONTAINS: return "contains";
    case KnowledgeEdgeKind::CALLS: return "calls";
    case KnowledgeEdgeKind::OWNS: return "owns";
    case KnowledgeEdgeKind::INHERITS: return "inherits";
    case KnowledgeEdgeKind::HAS_TYPE: return "has-type";
    case KnowledgeEdgeKind::READS: return "reads";
    case KnowledgeEdgeKind::WRITES: return "writes";
    case KnowledgeEdgeKind::ALIASES: return "aliases";
    case KnowledgeEdgeKind::CONSTRUCTS: return "constructs";
    case KnowledgeEdgeKind::DESTROYS: return "destroys";
    case KnowledgeEdgeKind::ALLOCATES: return "allocates";
    case KnowledgeEdgeKind::DEALLOCATES: return "deallocates";
    case KnowledgeEdgeKind::INITIALIZES_VPTR: return "initializes-vptr";
    case KnowledgeEdgeKind::RESOLVES_TO: return "resolves-to";
    case KnowledgeEdgeKind::RETURNS_TYPE: return "returns-type";
    case KnowledgeEdgeKind::EVIDENCE_FOR: return "evidence-for";
    case KnowledgeEdgeKind::IMPORTS: return "imports";
    case KnowledgeEdgeKind::ENTERS_AT: return "enters-at";
    }
    return "unknown";
}

uint64_t ProgramKnowledgeGraph::addNode(
    KnowledgeNodeKind kind, const std::string& key, const std::string& name,
    uint64_t address, uint64_t size, double confidence) {
    const auto existing = keys_.find(key);
    if (existing != keys_.end()) {
        KnowledgeNode* current = node(existing->second);
        if (current) {
            if (current->name.empty()) current->name = name;
            if (!current->address) current->address = address;
            current->size = std::max(current->size, size);
            current->confidence = std::max(current->confidence, confidence);
        }
        return existing->second;
    }
    KnowledgeNode result;
    result.id = nextNode_++;
    result.kind = kind;
    result.key = key;
    result.name = name;
    result.address = address;
    result.size = size;
    result.confidence = confidence;
    keys_[key] = result.id;
    nodes_.push_back(std::move(result));
    return nodes_.back().id;
}

uint64_t ProgramKnowledgeGraph::addEdge(
    uint64_t from, uint64_t to, KnowledgeEdgeKind kind, double confidence,
    const std::string& reason) {
    if (!from || !to) return 0;
    const auto existing = std::find_if(edges_.begin(), edges_.end(),
        [&](const KnowledgeEdge& edge) {
            return edge.from == from && edge.to == to && edge.kind == kind;
        });
    if (existing != edges_.end()) {
        existing->confidence = std::max(existing->confidence, confidence);
        if (existing->reason.empty()) existing->reason = reason;
        return existing->id;
    }
    KnowledgeEdge edge;
    edge.id = nextEdge_++;
    edge.from = from;
    edge.to = to;
    edge.kind = kind;
    edge.confidence = confidence;
    edge.reason = reason;
    edges_.push_back(std::move(edge));
    return edges_.back().id;
}

KnowledgeNode* ProgramKnowledgeGraph::node(uint64_t id) {
    if (!id || id > nodes_.size()) return nullptr;
    return &nodes_[static_cast<size_t>(id - 1)];
}

const KnowledgeNode* ProgramKnowledgeGraph::node(uint64_t id) const {
    if (!id || id > nodes_.size()) return nullptr;
    return &nodes_[static_cast<size_t>(id - 1)];
}

std::optional<uint64_t> ProgramKnowledgeGraph::find(
    const std::string& key) const {
    const auto found = keys_.find(key);
    return found == keys_.end() ? std::nullopt
                               : std::optional<uint64_t>(found->second);
}

std::string ProgramKnowledgeGraph::toJson() const {
    std::ostringstream output;
    output << "{\n  \"schema\": 1,\n  \"nodes\": [\n";
    for (size_t index = 0; index < nodes_.size(); ++index) {
        const KnowledgeNode& item = nodes_[index];
        output << "    {\"id\":" << item.id << ",\"kind\":\""
               << knowledgeNodeKindName(item.kind) << "\",\"key\":\""
               << jsonEscape(item.key) << "\",\"name\":\""
               << jsonEscape(item.name) << "\",\"address\":"
               << item.address << ",\"size\":" << item.size
               << ",\"confidence\":" << std::fixed << std::setprecision(3)
               << item.confidence << "}";
        output << (index + 1 == nodes_.size() ? "\n" : ",\n");
    }
    output << "  ],\n  \"edges\": [\n";
    for (size_t index = 0; index < edges_.size(); ++index) {
        const KnowledgeEdge& edge = edges_[index];
        output << "    {\"id\":" << edge.id << ",\"from\":" << edge.from
               << ",\"to\":" << edge.to << ",\"kind\":\""
               << knowledgeEdgeKindName(edge.kind)
               << "\",\"confidence\":" << std::fixed
               << std::setprecision(3) << edge.confidence
               << ",\"reason\":\"" << jsonEscape(edge.reason) << "\"}";
        output << (index + 1 == edges_.size() ? "\n" : ",\n");
    }
    output << "  ]\n}\n";
    return output.str();
}

ProgramKnowledgeGraph buildProgramKnowledgeGraph(
    const Program& program, const ProgramAnalysis& analysis) {
    ProgramKnowledgeGraph graph;
    const std::string binaryKey = "binary:" +
        (program.path.empty() ? std::string("<memory>") : program.path);
    const uint64_t binary = graph.addNode(KnowledgeNodeKind::BINARY,
        binaryKey, program.path, program.imageBase, 0, 1.0);
    const std::string moduleKey = "module:" + program.format + ":" + program.arch;
    const uint64_t module = graph.addNode(KnowledgeNodeKind::MODULE,
        moduleKey, program.format + " " + program.arch, program.imageBase, 0, 1.0);
    graph.addEdge(binary, module, KnowledgeEdgeKind::CONTAINS, 1.0,
                  "loader module");

    const uint64_t entryPoint = graph.addNode(KnowledgeNodeKind::ENTRY_POINT,
        "entry:" + addressKey(program.entryPoint), "real_entry_point",
        program.entryPoint, 0, program.entryPoint ? 1.0 : 0.0);
    if (program.entryPoint)
        graph.addEdge(module, entryPoint, KnowledgeEdgeKind::ENTERS_AT, 1.0,
                      "PE AddressOfEntryPoint");

    for (const DataRegion& region : program.dataRegions) {
        const uint64_t data = graph.addNode(KnowledgeNodeKind::DATA_REGION,
            "data-region:" + addressKey(region.address), region.name,
            region.address, region.size, 1.0);
        graph.addEdge(module, data, KnowledgeEdgeKind::CONTAINS, 1.0,
                      "loader data region");
    }

    std::map<std::string, uint64_t> libraries;
    for (const std::string& library : program.importedLibraries) {
        const uint64_t node = graph.addNode(
            KnowledgeNodeKind::IMPORT_LIBRARY, "import-library:" + library,
            library, 0, 0, 1.0);
        libraries[library] = node;
        graph.addEdge(module, node, KnowledgeEdgeKind::IMPORTS, 1.0,
                      "PE import descriptor");
    }
    for (const ImportSymbol& imported : program.imports) {
        const std::string importedName = imported.byOrdinal
            ? ("#" + std::to_string(imported.ordinal)) : imported.name;
        const uint64_t symbol = graph.addNode(KnowledgeNodeKind::IMPORT_SYMBOL,
            "import:" + imported.library + ":" + importedName,
            imported.library + "!" + importedName, imported.iatAddress,
            sizeof(uint64_t), 1.0);
        const auto library = libraries.find(imported.library);
        if (library != libraries.end())
            graph.addEdge(library->second, symbol, KnowledgeEdgeKind::CONTAINS,
                          1.0, imported.delayed ? "delay import" : "IAT import");
    }
    for (size_t index = 0; index < program.resources.size(); ++index) {
        const ResourceEntry& resource = program.resources[index];
        const std::string type = resource.typeName.empty()
            ? std::to_string(resource.typeId) : resource.typeName;
        const std::string name = resource.name.empty()
            ? std::to_string(resource.nameId) : resource.name;
        const uint64_t node = graph.addNode(KnowledgeNodeKind::RESOURCE,
            "resource:" + std::to_string(index), type + "/" + name,
            resource.dataAddress, resource.size, 1.0);
        graph.addEdge(module, node, KnowledgeEdgeKind::CONTAINS, 1.0,
                      "PE resource directory leaf");
    }

    std::map<uint64_t, uint64_t> functions;
    for (const auto& entry : analysis.functions()) {
        const AnalyzedFunction& analyzed = entry.second;
        const std::string key = "function:" + addressKey(entry.first);
        const uint64_t function = graph.addNode(KnowledgeNodeKind::FUNCTION,
            key, analyzed.function.name, entry.first, analyzed.function.size,
            analyzed.complete ? 0.95 : 0.45);
        functions[entry.first] = function;
        graph.addEdge(module, function, KnowledgeEdgeKind::CONTAINS, 1.0,
                      "function discovery");
        if (entry.first == program.entryPoint)
            graph.addEdge(entryPoint, function, KnowledgeEdgeKind::RESOLVES_TO,
                          1.0, "real entry function");
        const uint64_t returnType = graph.addNode(KnowledgeNodeKind::DATA_TYPE,
            "type:" + typeKey(analyzed.signature.returnType),
            analyzed.signature.returnType.name(), 0, 0, 0.75);
        graph.addEdge(function, returnType, KnowledgeEdgeKind::RETURNS_TYPE,
                      0.75, "interprocedural signature inference");
        for (size_t index = 0; index < analyzed.signature.parameters.size(); ++index) {
            const FunctionParameter& parameter = analyzed.signature.parameters[index];
            const uint64_t variable = graph.addNode(KnowledgeNodeKind::PARAMETER,
                key + ":parameter:" + std::to_string(index), parameter.name,
                entry.first, parameter.type.bits / 8, 0.72);
            const uint64_t type = graph.addNode(KnowledgeNodeKind::DATA_TYPE,
                "type:" + typeKey(parameter.type), parameter.type.name(), 0, 0,
                0.72);
            graph.addEdge(function, variable, KnowledgeEdgeKind::OWNS, 0.9,
                          "ABI parameter");
            graph.addEdge(variable, type, KnowledgeEdgeKind::HAS_TYPE, 0.72,
                          "data-flow type solver");
        }
    }
    for (const auto& entry : analysis.functions()) {
        for (uint64_t callee : entry.second.callees) {
            const auto callerNode = functions.find(entry.first);
            const auto calleeNode = functions.find(callee);
            if (callerNode != functions.end() && calleeNode != functions.end())
                graph.addEdge(callerNode->second, calleeNode->second,
                              KnowledgeEdgeKind::CALLS, 0.9,
                              "direct call-graph edge");
        }
    }

    const CppRecoveryResult& cpp = analysis.cppTypes();
    std::map<std::string, uint64_t> classes;
    auto classNode = [&](const std::string& name, double confidence) {
        const auto found = classes.find(name);
        if (found != classes.end()) return found->second;
        const uint64_t id = graph.addNode(KnowledgeNodeKind::CLASS_TYPE,
            "class:" + name, name, 0, 0, confidence);
        classes[name] = id;
        graph.addEdge(module, id, KnowledgeEdgeKind::CONTAINS, confidence,
                      "C++ class candidate");
        return id;
    };
    for (const CppClassInfo& info : cpp.classes) {
        const uint64_t owner = classNode(info.name, info.confidence);
        if (KnowledgeNode* node = graph.node(owner))
            node->evidence.insert(node->evidence.end(), info.evidence.begin(),
                                  info.evidence.end());
        if (info.vtableAddress) {
            const uint64_t vtable = graph.addNode(KnowledgeNodeKind::VTABLE,
                "vtable:" + addressKey(info.vtableAddress), info.name + "::vtable",
                info.vtableAddress, 0, 0.98);
            graph.addEdge(owner, vtable, KnowledgeEdgeKind::OWNS, 0.98,
                          "ABI vtable");
        }
        for (const CppBaseClass& base : info.bases)
            graph.addEdge(owner, classNode(base.name, 0.8),
                          KnowledgeEdgeKind::INHERITS, 0.9,
                          base.isVirtual ? "virtual base" : "base subobject");
        for (const CppFieldInfo& field : info.fields) {
            const uint64_t member = graph.addNode(KnowledgeNodeKind::FIELD,
                "class:" + info.name + ":field:" +
                    std::to_string(field.byteOffset),
                field.name, 0, field.byteSize, field.confidence);
            graph.addEdge(owner, member, KnowledgeEdgeKind::OWNS,
                          field.confidence, "recovered object layout");
            if (!field.typeName.empty()) {
                const uint64_t type = graph.addNode(KnowledgeNodeKind::DATA_TYPE,
                    "type:cpp:" + field.typeName, field.typeName, 0, 0,
                    field.confidence);
                graph.addEdge(member, type, KnowledgeEdgeKind::HAS_TYPE,
                              field.confidence, "field type recovery");
            }
        }
        for (const CppMethodInfo& method : info.methods) {
            const auto function = functions.find(method.address);
            if (function != functions.end())
                graph.addEdge(owner, function->second, KnowledgeEdgeKind::OWNS,
                              method.confidence, "recovered member function");
        }
    }
    for (const Symbol& symbol : program.symbols) {
        if (symbol.isFunction) continue;
        const uint64_t global = graph.addNode(KnowledgeNodeKind::GLOBAL,
            "global:" + addressKey(symbol.addr), symbol.name, symbol.addr,
            symbol.size, 0.85);
        graph.addEdge(module, global, KnowledgeEdgeKind::CONTAINS, 0.9,
                      "loader symbol");
    }
    for (const CppObjectCandidate& object : cpp.objectGraph.objects) {
        const uint64_t objectNode = graph.addNode(KnowledgeNodeKind::OBJECT,
            "object:" + std::to_string(object.id), object.className,
            object.storageAddress, object.inferredSize, object.confidence);
        graph.addEdge(module, objectNode, KnowledgeEdgeKind::CONTAINS,
                      object.confidence, "object lifetime candidate");
        graph.addEdge(objectNode, classNode(object.className, object.confidence),
                      KnowledgeEdgeKind::HAS_TYPE, object.confidence,
                      "object class candidate");
        for (const CppLifetimeEvent& event : object.lifetime) {
            const auto function = functions.find(event.functionAddress);
            if (function == functions.end()) continue;
            KnowledgeEdgeKind edge = KnowledgeEdgeKind::CONSTRUCTS;
            if (event.kind == CppLifetimeEventKind::DESTROY)
                edge = KnowledgeEdgeKind::DESTROYS;
            else if (event.kind == CppLifetimeEventKind::ALLOCATE)
                edge = KnowledgeEdgeKind::ALLOCATES;
            else if (event.kind == CppLifetimeEventKind::DEALLOCATE)
                edge = KnowledgeEdgeKind::DEALLOCATES;
            graph.addEdge(function->second, objectNode, edge, event.confidence,
                          "object lifetime event");
        }
    }
    for (const CppVptrWrite& write : cpp.objectGraph.vptrWrites) {
        const auto function = functions.find(write.functionAddress);
        const auto owner = classes.find(write.className);
        const auto vtable = graph.find("vtable:" + addressKey(write.vtableAddress));
        if (function != functions.end() && owner != classes.end())
            graph.addEdge(function->second, owner->second,
                          KnowledgeEdgeKind::INITIALIZES_VPTR,
                          write.confidence, "known vtable stored through this");
        if (owner != classes.end() && vtable)
            graph.addEdge(owner->second, *vtable, KnowledgeEdgeKind::OWNS,
                          write.confidence, "vptr initialization target");
    }
    for (const CppVirtualCallSite& call : cpp.objectGraph.virtualCalls) {
        const uint64_t site = graph.addNode(KnowledgeNodeKind::CALL_SITE,
            "vcall:" + addressKey(call.functionAddress) + ":" +
                addressKey(call.instructionAddress),
            call.className + "::slot" + std::to_string(call.slot),
            call.instructionAddress, 0, call.confidence);
        const auto function = functions.find(call.functionAddress);
        if (function != functions.end())
            graph.addEdge(function->second, site, KnowledgeEdgeKind::CONTAINS,
                          call.confidence, "virtual call site");
        for (uint64_t target : call.resolvedTargets) {
            const auto resolved = functions.find(target);
            if (resolved != functions.end())
                graph.addEdge(site, resolved->second,
                              KnowledgeEdgeKind::RESOLVES_TO, call.confidence,
                              "vtable slot resolution");
        }
    }
    for (size_t index = 0; index < cpp.objectGraph.runtimeOperations.size(); ++index) {
        const CppRuntimeOperation& operation =
            cpp.objectGraph.runtimeOperations[index];
        const uint64_t runtime = graph.addNode(
            KnowledgeNodeKind::RUNTIME_OPERATION,
            "runtime:" + addressKey(operation.functionAddress) + ":" +
                std::to_string(index),
            operation.referencedType, operation.instructionAddress, 0,
            operation.confidence);
        const auto function = functions.find(operation.functionAddress);
        if (function != functions.end())
            graph.addEdge(function->second, runtime,
                          KnowledgeEdgeKind::CONTAINS, operation.confidence,
                          "C++ runtime semantic operation");
        if (!operation.className.empty())
            graph.addEdge(runtime,
                          classNode(operation.className, operation.confidence),
                          KnowledgeEdgeKind::HAS_TYPE, operation.confidence,
                          "runtime type evidence");
    }
    return graph;
}

} // namespace centrifuge
