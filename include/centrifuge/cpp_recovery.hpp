// centrifuge - C++ ABI metadata, class, inheritance, and vtable recovery
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "centrifuge/loader.hpp"

namespace centrifuge {

class ProgramAnalysis;
class SleighEngine;

enum class CppAbi { ITANIUM, MSVC };

enum class CppEvidenceKind {
    SYMBOL, RTTI, VTABLE, VPTR_STORE, THIS_PARAMETER, THIS_FORWARD,
    FIELD_READ, FIELD_WRITE, DIRECT_CALL, VIRTUAL_CALL, ALLOCATION,
    DEALLOCATION, LIFETIME, THUNK, EXCEPTION_TYPE, CROSS_MODULE,
};

struct CppEvidence {
    CppEvidenceKind kind = CppEvidenceKind::SYMBOL;
    uint64_t address = 0;
    uint64_t functionAddress = 0;
    double confidence = 0;
    std::string description;
};

enum class CppMethodRole {
    UNKNOWN, METHOD, CONSTRUCTOR, COPY_CONSTRUCTOR, MOVE_CONSTRUCTOR,
    BASE_DESTRUCTOR, COMPLETE_DESTRUCTOR, DELETING_DESTRUCTOR,
    COPY_ASSIGNMENT, MOVE_ASSIGNMENT, VIRTUAL_METHOD, PURE_VIRTUAL,
    ADJUSTOR_THUNK, COVARIANT_RETURN_THUNK, FACTORY, ALLOCATOR,
    DEALLOCATOR,
};

struct CppFieldInfo {
    int64_t byteOffset = 0;
    uint64_t byteSize = 0;
    std::string name;
    std::string typeName;
    size_t readCount = 0;
    size_t writeCount = 0;
    bool isVptr = false;
    bool isVbptr = false;
    bool isBaseSubobject = false;
    double confidence = 0;
    std::vector<CppEvidence> evidence;
};

struct CppMethodInfo {
    uint64_t address = 0;
    std::string name;
    CppMethodRole role = CppMethodRole::UNKNOWN;
    uint64_t thisRegister = 0;
    int64_t thisAdjustment = 0;
    int64_t returnAdjustment = 0;
    bool hasThis = false;
    bool isVirtual = false;
    size_t virtualSlot = 0;
    double confidence = 0;
    // Visible member identity recovered from the symbol: owning class and
    // bare member name ("Square", "area" / "~Square").  Drives readable
    // ClassName_method renaming in decompiled output.
    std::string ownerClass;
    std::string memberName;
    std::vector<CppEvidence> evidence;
};

enum class CppLifetimeEventKind {
    ALLOCATE, CONSTRUCT, COPY_CONSTRUCT, MOVE_CONSTRUCT, ASSIGN,
    DESTROY, DEALLOCATE,
};

struct CppLifetimeEvent {
    CppLifetimeEventKind kind = CppLifetimeEventKind::CONSTRUCT;
    uint64_t address = 0;
    uint64_t functionAddress = 0;
    double confidence = 0;
};

struct CppObjectCandidate {
    uint64_t id = 0;
    std::string className;
    uint64_t allocationSite = 0;
    uint64_t storageAddress = 0;
    uint64_t inferredSize = 0;
    bool placementNew = false;
    double confidence = 0;
    std::vector<CppLifetimeEvent> lifetime;
    std::vector<CppEvidence> evidence;
};

struct CppVptrWrite {
    uint64_t functionAddress = 0;
    uint64_t instructionAddress = 0;
    std::string className;
    int64_t objectOffset = 0;
    uint64_t vtableAddress = 0;
    double confidence = 0;
};

struct CppVirtualCallSite {
    uint64_t functionAddress = 0;
    uint64_t instructionAddress = 0;
    std::string className;
    int64_t vptrOffset = 0;
    size_t slot = 0;
    uint64_t resolvedTarget = 0;
    std::vector<uint64_t> resolvedTargets;
    double confidence = 0;
};

enum class CppRuntimeOperationKind {
    DYNAMIC_CAST, TYPEID, THROW_EXCEPTION, BEGIN_CATCH, END_CATCH,
    RETHROW, PLACEMENT_NEW,
};

struct CppRuntimeOperation {
    CppRuntimeOperationKind kind = CppRuntimeOperationKind::DYNAMIC_CAST;
    uint64_t functionAddress = 0;
    uint64_t instructionAddress = 0;
    std::string className;
    std::string referencedType;
    uint64_t landingPad = 0;
    int64_t action = 0;
    double confidence = 0;
    std::vector<CppEvidence> evidence;
};

struct CppMemberPointerInfo {
    uint64_t address = 0;
    std::string ownerClass;
    std::string name;
    int64_t functionOrVtableOffset = 0;
    int64_t thisAdjustment = 0;
    bool isVirtual = false;
    double confidence = 0;
};

struct CppObjectRecoveryGraph {
    std::vector<CppMethodInfo> methods;
    std::vector<CppObjectCandidate> objects;
    std::vector<CppVptrWrite> vptrWrites;
    std::vector<CppVirtualCallSite> virtualCalls;
    std::vector<CppRuntimeOperation> runtimeOperations;
    std::vector<CppMemberPointerInfo> memberPointers;
    std::map<uint64_t, std::string> functionClasses;
    std::vector<CppEvidence> evidence;
};

struct CppVirtualFunction {
    size_t slot = 0;
    uint64_t address = 0;
    std::string name;
};

struct CppVtableGroup {
    uint64_t address = 0;
    int64_t offsetToTop = 0;
    std::string baseSubobject;
    std::vector<CppVirtualFunction> virtualFunctions;
};

struct CppTemplateInfo {
    bool isInstantiation = false;
    std::string primaryName;
    std::vector<std::string> arguments;
};

struct CppBaseClass {
    std::string name;
    uint64_t typeInfoAddress = 0;
    int64_t byteOffset = 0;
    bool isVirtual = false;
};

struct CppClassInfo {
    std::string name;
    std::string stableIdentity;
    CppAbi abi = CppAbi::ITANIUM;
    uint64_t typeInfoAddress = 0;
    uint64_t vtableAddress = 0;
    CppTemplateInfo templateInfo;
    std::vector<CppBaseClass> bases;
    std::vector<CppVirtualFunction> virtualFunctions;
    std::vector<CppVtableGroup> vtableGroups;
    std::vector<CppFieldInfo> fields;
    std::vector<CppMethodInfo> methods;
    std::vector<std::string> staticMembers;
    uint64_t inferredSize = 0;
    uint64_t inferredAlignment = 1;
    uint64_t inferredPadding = 0;
    bool isAbstract = false;
    bool hasVirtualInheritance = false;
    std::vector<int64_t> vbptrOffsets;
    std::string libraryPattern;
    double confidence = 0;
    std::vector<CppEvidence> evidence;
};

struct CppRecoveryResult {
    std::vector<CppClassInfo> classes;
    CppObjectRecoveryGraph objectGraph;
    std::vector<std::string> diagnostics;
};

CppRecoveryResult recoverCppTypes(const Program& program);
CppRecoveryResult mergeCppRecoveryResults(
    const std::vector<CppRecoveryResult>& modules);
void refineCppObjectGraph(const Program& program, const SleighEngine& engine,
                          const ProgramAnalysis& analysis,
                          CppRecoveryResult& recovery);

} // namespace centrifuge
