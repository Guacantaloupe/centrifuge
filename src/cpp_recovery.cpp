// centrifuge - Itanium and MSVC C++ runtime metadata recovery
#include "centrifuge/cpp_recovery.hpp"

#include "centrifuge/ir.hpp"
#include "centrifuge/sleigh.hpp"
#include "centrifuge/import_prototype.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace centrifuge {
namespace {

std::string itaniumTypeName(std::string encoding) {
    if (!encoding.empty() && encoding.front() == 'N' && encoding.back() == 'E')
        encoding = encoding.substr(1, encoding.size() - 2);
    std::string result;
    size_t at = 0;
    while (at < encoding.size()) {
        if (!std::isdigit(static_cast<unsigned char>(encoding[at]))) break;
        size_t digits = at;
        while (at < encoding.size() &&
               std::isdigit(static_cast<unsigned char>(encoding[at])))
            ++at;
        size_t length = 0;
        try {
            length = static_cast<size_t>(
                std::stoull(encoding.substr(digits, at - digits)));
        } catch (...) {
            break;
        }
        if (!length || length > encoding.size() - at) break;
        if (!result.empty()) result += "::";
        result += encoding.substr(at, length);
        at += length;
    }
    return result.empty() ? encoding : result;
}

std::string builtinTypeName(char code) {
    switch (code) {
    case 'v': return "void"; case 'b': return "bool";
    case 'c': return "char"; case 'a': return "signed char";
    case 'h': return "unsigned char"; case 's': return "short";
    case 't': return "unsigned short"; case 'i': return "int";
    case 'j': return "unsigned int"; case 'l': return "long";
    case 'm': return "unsigned long"; case 'x': return "long long";
    case 'y': return "unsigned long long"; case 'f': return "float";
    case 'd': return "double"; case 'e': return "long double";
    default: return {};
    }
}

std::string parseItaniumType(const std::string& encoding, size_t& at);

std::string parseItaniumComponent(const std::string& encoding, size_t& at) {
    if (at >= encoding.size() ||
        !std::isdigit(static_cast<unsigned char>(encoding[at]))) return {};
    size_t length = 0;
    while (at < encoding.size() &&
           std::isdigit(static_cast<unsigned char>(encoding[at]))) {
        length = length * 10 + static_cast<size_t>(encoding[at] - '0');
        ++at;
    }
    if (!length || length > encoding.size() - at) return {};
    std::string name = encoding.substr(at, length);
    at += length;
    if (at < encoding.size() && encoding[at] == 'I') {
        ++at;
        std::vector<std::string> arguments;
        while (at < encoding.size() && encoding[at] != 'E') {
            const size_t before = at;
            std::string argument = parseItaniumType(encoding, at);
            if (argument.empty() || at == before) break;
            arguments.push_back(std::move(argument));
        }
        if (at < encoding.size() && encoding[at] == 'E') ++at;
        name += "<";
        for (size_t index = 0; index < arguments.size(); ++index) {
            if (index) name += ", ";
            name += arguments[index];
        }
        name += ">";
    }
    return name;
}

std::string parseItaniumType(const std::string& encoding, size_t& at) {
    if (at >= encoding.size()) return {};
    const char code = encoding[at];
    if (const std::string builtin = builtinTypeName(code); !builtin.empty()) {
        ++at;
        return builtin;
    }
    if (code == 'P' || code == 'R' || code == 'O' || code == 'K') {
        ++at;
        std::string nested = parseItaniumType(encoding, at);
        if (code == 'P') return nested + "*";
        if (code == 'R') return nested + "&";
        if (code == 'O') return nested + "&&";
        return "const " + nested;
    }
    if (code == 'N') {
        ++at;
        std::string result;
        while (at < encoding.size() && encoding[at] != 'E') {
            std::string component = parseItaniumComponent(encoding, at);
            if (component.empty()) break;
            if (!result.empty()) result += "::";
            result += component;
        }
        if (at < encoding.size() && encoding[at] == 'E') ++at;
        return result;
    }
    return parseItaniumComponent(encoding, at);
}

std::string demangleItaniumClass(const std::string& encoding) {
    size_t at = 0;
    const std::string parsed = parseItaniumType(encoding, at);
    return parsed.empty() ? itaniumTypeName(encoding) : parsed;
}

CppTemplateInfo templateInfo(const std::string& name) {
    CppTemplateInfo info;
    const size_t open = name.find('<');
    if (open == std::string::npos || name.back() != '>') return info;
    info.isInstantiation = true;
    info.primaryName = name.substr(0, open);
    std::string current;
    unsigned depth = 0;
    for (size_t at = open + 1; at + 1 < name.size(); ++at) {
        const char ch = name[at];
        if (ch == '<') ++depth;
        if (ch == '>') --depth;
        if (ch == ',' && depth == 0) {
            if (!current.empty() && current.front() == ' ') current.erase(0, 1);
            info.arguments.push_back(current);
            current.clear();
        } else {
            current += ch;
        }
    }
    if (!current.empty()) {
        if (current.front() == ' ') current.erase(0, 1);
        info.arguments.push_back(std::move(current));
    }
    return info;
}

std::string classNameFromSymbol(const std::string& symbol, CppAbi& abi,
                                bool& vtable, bool& typeInfo) {
    vtable = typeInfo = false;
    if (symbol.rfind("_ZTV", 0) == 0 || symbol.rfind("_ZTI", 0) == 0) {
        abi = CppAbi::ITANIUM;
        vtable = symbol.rfind("_ZTV", 0) == 0;
        typeInfo = !vtable;
        return demangleItaniumClass(symbol.substr(4));
    }
    if (symbol.rfind("??_7", 0) == 0) {
        abi = CppAbi::MSVC;
        vtable = true;
        const size_t end = symbol.find("@@", 4);
        return end == std::string::npos ? symbol.substr(4)
                                        : symbol.substr(4, end - 4);
    }
    if (symbol.rfind("??_R0", 0) == 0) {
        abi = CppAbi::MSVC;
        typeInfo = true;
        const size_t end = symbol.find("@@", 5);
        return end == std::string::npos ? symbol.substr(5)
                                        : symbol.substr(5, end - 5);
    }
    return {};
}

bool readPointer(const Program& program, uint64_t address, int pointerSize,
                 uint64_t& value) {
    value = 0;
    if (!program.memory.read(address, &value, static_cast<size_t>(pointerSize)))
        return false;
    if (pointerSize == 4) value &= 0xffffffffULL;
    return true;
}

std::string functionName(const Program& program, uint64_t address) {
    for (const Symbol& symbol : program.symbols)
        if (symbol.isFunction && symbol.addr == address) return symbol.name;
    // Match the analysis naming convention (analysis.cpp funName) so
    // recovered vtables do not name targets in yet another FUN_ format.
    const bool is64 = program.arch != "x86" && program.arch != "arm" &&
                      program.arch != "mips" && program.arch != "riscv32";
    char buf[40];
    std::snprintf(buf, sizeof(buf), is64 ? "FUN_%016llX" : "FUN_%08llX",
                  static_cast<unsigned long long>(address));
    return buf;
}

std::pair<std::string, std::string> visibleMemberName(
    const std::string& symbol) {
    const size_t separator = symbol.rfind("::");
    if (separator != std::string::npos)
        return {symbol.substr(0, separator), symbol.substr(separator + 2)};
    if (symbol.rfind("_ZTh", 0) == 0 || symbol.rfind("_ZTc", 0) == 0) {
        const size_t target = symbol.find("_ZN", 4);
        if (target != std::string::npos)
            return visibleMemberName(symbol.substr(target));
    }
    if (symbol.rfind("??0", 0) == 0 || symbol.rfind("??1", 0) == 0 ||
        symbol.rfind("??4", 0) == 0 || symbol.rfind("??_G", 0) == 0 ||
        symbol.rfind("??_E", 0) == 0) {
        const size_t prefix = symbol[2] == '_' ? 4 : 3;
        const size_t end = symbol.find("@@", prefix);
        if (end != std::string::npos) {
            const std::string owner = symbol.substr(prefix, end - prefix);
            if (symbol.rfind("??0", 0) == 0) return {owner, owner};
            if (symbol.rfind("??4", 0) == 0) return {owner, "operator="};
            return {owner, "~" + owner};
        }
    }
    if (symbol.rfind("_ZN", 0) == 0) {
        size_t at = 3;
        std::vector<std::string> components;
        while (at < symbol.size() && symbol[at] != 'E') {
            if (symbol.compare(at, 2, "C1") == 0 ||
                symbol.compare(at, 2, "C2") == 0 ||
                symbol.compare(at, 2, "C3") == 0) {
                if (!components.empty()) {
                    std::string owner;
                    for (const std::string& component : components) {
                        if (!owner.empty()) owner += "::";
                        owner += component;
                    }
                    return {owner, components.back()};
                }
                break;
            }
            if (symbol.compare(at, 2, "D0") == 0 ||
                symbol.compare(at, 2, "D1") == 0 ||
                symbol.compare(at, 2, "D2") == 0) {
                if (!components.empty()) {
                    std::string owner;
                    for (const std::string& component : components) {
                        if (!owner.empty()) owner += "::";
                        owner += component;
                    }
                    return {owner, "~" + components.back()};
                }
                break;
            }
            if (symbol.compare(at, 2, "aS") == 0 && !components.empty()) {
                std::string owner;
                for (const std::string& component : components) {
                    if (!owner.empty()) owner += "::";
                    owner += component;
                }
                return {owner, "operator="};
            }
            if (!std::isdigit(static_cast<unsigned char>(symbol[at]))) break;
            size_t length = 0;
            while (at < symbol.size() &&
                   std::isdigit(static_cast<unsigned char>(symbol[at]))) {
                length = length * 10 + static_cast<size_t>(symbol[at] - '0');
                ++at;
            }
            if (!length || length > symbol.size() - at) break;
            components.push_back(symbol.substr(at, length));
            at += length;
        }
        if (components.size() >= 2) {
            std::string owner;
            for (size_t index = 0; index + 1 < components.size(); ++index) {
                if (index) owner += "::";
                owner += components[index];
            }
            return {owner, components.back()};
        }
    }
    if (!symbol.empty() && symbol[0] == '?' && symbol.size() > 1) {
        const size_t methodEnd = symbol.find('@', 1);
        const size_t classEnd = methodEnd == std::string::npos
            ? std::string::npos : symbol.find("@@", methodEnd + 1);
        if (methodEnd != std::string::npos && classEnd != std::string::npos)
            return {symbol.substr(methodEnd + 1, classEnd - methodEnd - 1),
                    symbol.substr(1, methodEnd - 1)};
    }
    return {};
}

CppMethodRole symbolMethodRole(const std::string& symbol,
                               const std::string& owner,
                               const std::string& member) {
    if (symbol.rfind("_ZTh", 0) == 0 || symbol.find("adjustor thunk") != std::string::npos)
        return CppMethodRole::ADJUSTOR_THUNK;
    if (symbol.rfind("_ZTc", 0) == 0 || symbol.find("covariant return thunk") != std::string::npos)
        return CppMethodRole::COVARIANT_RETURN_THUNK;
    if (symbol.find("D0") != std::string::npos ||
        symbol.rfind("??_G", 0) == 0 || symbol.rfind("??_E", 0) == 0 ||
        symbol.find("deleting destructor") != std::string::npos)
        return CppMethodRole::DELETING_DESTRUCTOR;
    if (symbol.find("D1") != std::string::npos)
        return CppMethodRole::COMPLETE_DESTRUCTOR;
    if (symbol.find("D2") != std::string::npos)
        return CppMethodRole::BASE_DESTRUCTOR;
    if (!owner.empty() && (member == owner ||
        member == owner.substr(owner.rfind("::") == std::string::npos
                                  ? 0 : owner.rfind("::") + 2))) {
        if (symbol.find("move") != std::string::npos ||
            symbol.find("EOS_") != std::string::npos ||
            symbol.find("$$QEAV") != std::string::npos)
            return CppMethodRole::MOVE_CONSTRUCTOR;
        if (symbol.find("copy") != std::string::npos ||
            symbol.find("ERKS_") != std::string::npos ||
            symbol.find("AEBV") != std::string::npos)
            return CppMethodRole::COPY_CONSTRUCTOR;
        return CppMethodRole::CONSTRUCTOR;
    }
    if (!member.empty() && member.front() == '~')
        return CppMethodRole::COMPLETE_DESTRUCTOR;
    if (member == "operator=") {
        if (symbol.find("move") != std::string::npos ||
            symbol.find("EOS_") != std::string::npos ||
            symbol.find("$$QEA") != std::string::npos)
            return CppMethodRole::MOVE_ASSIGNMENT;
        return CppMethodRole::COPY_ASSIGNMENT;
    }
    if (member.find("operator new") != std::string::npos)
        return CppMethodRole::ALLOCATOR;
    if (member.find("operator delete") != std::string::npos)
        return CppMethodRole::DEALLOCATOR;
    return owner.empty() ? CppMethodRole::UNKNOWN : CppMethodRole::METHOD;
}

bool isAllocatorName(const std::string& name) {
    return name == "malloc" || name == "calloc" || name == "realloc" ||
           name == "operator new" || name.find("operator new") != std::string::npos ||
           name.rfind("_Zn", 0) == 0;
}

bool isDeallocatorName(const std::string& name) {
    return name == "free" || name == "operator delete" ||
           name.find("operator delete") != std::string::npos ||
           name.rfind("_Zdl", 0) == 0 || name.rfind("_Zda", 0) == 0;
}

bool containsName(const std::string& name, const std::string& fragment) {
    return name.find(fragment) != std::string::npos;
}

bool isPlacementAllocatorName(const std::string& name) {
    return containsName(name, "placement new") ||
           containsName(name, "operator new(unsigned long, void*)") ||
           name.rfind("_ZnwmPv", 0) == 0 || name.rfind("_ZnwjPv", 0) == 0 ||
           name.rfind("??2@YAPEAX_KPEAX", 0) == 0;
}

std::optional<CppRuntimeOperationKind> runtimeOperationKind(
    const std::string& name) {
    if (name == "__dynamic_cast" || containsName(name, "__RTDynamicCast"))
        return CppRuntimeOperationKind::DYNAMIC_CAST;
    if (containsName(name, "typeid") || containsName(name, "__RTtypeid"))
        return CppRuntimeOperationKind::TYPEID;
    if (name == "__cxa_throw" || containsName(name, "_CxxThrowException"))
        return CppRuntimeOperationKind::THROW_EXCEPTION;
    if (name == "__cxa_begin_catch")
        return CppRuntimeOperationKind::BEGIN_CATCH;
    if (name == "__cxa_end_catch")
        return CppRuntimeOperationKind::END_CATCH;
    if (name == "__cxa_rethrow" || name == "_CxxRethrowException")
        return CppRuntimeOperationKind::RETHROW;
    if (isPlacementAllocatorName(name))
        return CppRuntimeOperationKind::PLACEMENT_NEW;
    return std::nullopt;
}

int64_t itaniumThisAdjustment(const std::string& name) {
    if (name.rfind("_ZTh", 0) != 0) return 0;
    size_t at = 4;
    int sign = 1;
    if (at < name.size() && name[at] == 'n') {
        sign = -1;
        ++at;
    }
    uint64_t magnitude = 0;
    bool any = false;
    while (at < name.size() &&
           std::isdigit(static_cast<unsigned char>(name[at]))) {
        any = true;
        magnitude = magnitude * 10 + static_cast<uint64_t>(name[at] - '0');
        ++at;
    }
    if (!any || magnitude > static_cast<uint64_t>(
            std::numeric_limits<int64_t>::max())) return 0;
    return sign * static_cast<int64_t>(magnitude);
}

std::string standardLibraryPattern(const std::string& primary) {
    if (primary == "std::vector" || primary == "vector") return "std::vector";
    if (primary == "std::basic_string" || primary == "basic_string" ||
        primary == "std::__cxx11::basic_string") return "std::basic_string";
    if (primary == "std::map" || primary == "map") return "std::map";
    if (primary == "std::unordered_map" || primary == "unordered_map")
        return "std::unordered_map";
    if (primary == "std::unique_ptr" || primary == "unique_ptr")
        return "std::unique_ptr";
    if (primary == "std::shared_ptr" || primary == "shared_ptr")
        return "std::shared_ptr";
    if (primary == "std::function" || primary == "function")
        return "std::function";
    return {};
}

uint64_t naturalAlignment(uint64_t size) {
    if (size >= 8) return 8;
    if (size >= 4) return 4;
    if (size >= 2) return 2;
    return 1;
}

struct SymbolicObjectAddress {
    bool valid = false;
    bool constant = false;
    uint64_t constantValue = 0;
    int64_t offset = 0;
    unsigned dereferenceDepth = 0;
    int64_t firstDereferenceOffset = 0;
    int64_t lastDereferenceOffset = 0;
    // The chain began at a register seeded as the object pointer (`this` or
    // the first parameter).  Distinguishes vptr-shaped chains from indirect
    // calls through unrelated data pointers.
    bool fromThis = false;
};

} // namespace

CppRecoveryResult recoverCppTypes(const Program& program) {
    CppRecoveryResult result;
    const int pointerSize = program.format == "ELF32" ||
                                    program.format == "PE32"
                                ? 4 : 8;
    std::map<std::pair<CppAbi, std::string>, size_t> classIndex;
    std::map<uint64_t, size_t> typeInfoIndex;
    auto getClass = [&](CppAbi abi, const std::string& name) -> CppClassInfo& {
        const auto key = std::make_pair(abi, name);
        auto found = classIndex.find(key);
        if (found != classIndex.end()) return result.classes[found->second];
        CppClassInfo info;
        info.name = name;
        info.abi = abi;
        info.stableIdentity = (abi == CppAbi::ITANIUM ? "itanium:" : "msvc:") +
                              name;
        info.templateInfo = templateInfo(name);
        info.libraryPattern = standardLibraryPattern(
            info.templateInfo.isInstantiation ? info.templateInfo.primaryName
                                               : info.name);
        const size_t index = result.classes.size();
        result.classes.push_back(std::move(info));
        classIndex[key] = index;
        return result.classes.back();
    };

    for (const Symbol& symbol : program.symbols) {
        CppAbi abi = CppAbi::ITANIUM;
        bool vtable = false, typeInfo = false;
        const std::string name = classNameFromSymbol(symbol.name, abi,
                                                      vtable, typeInfo);
        if (name.empty()) continue;
        CppClassInfo& info = getClass(abi, name);
        if (vtable) {
            info.vtableAddress = symbol.addr;
            info.confidence = std::max(info.confidence, 0.98);
            info.evidence.push_back({CppEvidenceKind::VTABLE, symbol.addr, 0,
                                     0.98, "ABI vtable symbol"});
        }
        if (typeInfo) {
            info.typeInfoAddress = symbol.addr;
            typeInfoIndex[symbol.addr] = classIndex[{abi, name}];
            info.confidence = std::max(info.confidence, 0.99);
            info.evidence.push_back({CppEvidenceKind::RTTI, symbol.addr, 0,
                                     0.99, "ABI runtime type-information symbol"});
        }
    }

    for (CppClassInfo& info : result.classes) {
        if (!info.vtableAddress) continue;
        if (info.abi == CppAbi::ITANIUM) {
            uint64_t header = info.vtableAddress;
            for (size_t groupIndex = 0; groupIndex < 32; ++groupIndex) {
                uint64_t rawOffset = 0, typeInfo = 0;
                if (!readPointer(program, header, pointerSize, rawOffset) ||
                    !readPointer(program, header + pointerSize, pointerSize,
                                 typeInfo))
                    break;
                const int64_t offsetToTop = pointerSize == 4
                    ? static_cast<int64_t>(static_cast<int32_t>(rawOffset))
                    : static_cast<int64_t>(rawOffset);
                if (groupIndex && typeInfo != info.typeInfoAddress) break;
                CppVtableGroup group;
                group.address = header + 2 * pointerSize;
                group.offsetToTop = offsetToTop;
                uint64_t cursor = group.address;
                for (size_t slot = 0; slot < 256;
                     ++slot, cursor += pointerSize) {
                    uint64_t target = 0;
                    if (!readPointer(program, cursor, pointerSize, target) ||
                        !program.memory.isExecutable(target))
                        break;
                    group.virtualFunctions.push_back(
                        {slot, target, functionName(program, target)});
                }
                if (group.virtualFunctions.empty()) break;
                header = group.address +
                         group.virtualFunctions.size() * pointerSize;
                info.vtableGroups.push_back(std::move(group));
            }
            if (!info.vtableGroups.empty())
                info.virtualFunctions = info.vtableGroups.front().virtualFunctions;
        } else {
            CppVtableGroup group;
            group.address = info.vtableAddress;
            uint64_t cursor = info.vtableAddress;
            for (size_t slot = 0; slot < 256; ++slot, cursor += pointerSize) {
                uint64_t target = 0;
                if (!readPointer(program, cursor, pointerSize, target) ||
                    !program.memory.isExecutable(target))
                    break;
                group.virtualFunctions.push_back(
                    {slot, target, functionName(program, target)});
            }
            info.virtualFunctions = group.virtualFunctions;
            if (!group.virtualFunctions.empty())
                info.vtableGroups.push_back(std::move(group));
        }
    }

    // Itanium __si_class_type_info has one base pointer immediately after the
    // common vptr/name fields.  __vmi_class_type_info follows those fields
    // with flags, count, and (type, offset_flags) entries.
    for (CppClassInfo& info : result.classes) {
        if (info.abi != CppAbi::ITANIUM || !info.typeInfoAddress) continue;
        uint64_t baseType = 0;
        if (readPointer(program, info.typeInfoAddress + 2 * pointerSize,
                        pointerSize, baseType) && typeInfoIndex.count(baseType)) {
            const CppClassInfo& base = result.classes[typeInfoIndex[baseType]];
            info.bases.push_back({base.name, baseType, 0, false});
            continue;
        }
        uint32_t flags = 0, count = 0;
        if (!program.memory.read(info.typeInfoAddress + 2 * pointerSize,
                                 &flags, sizeof(flags)) ||
            !program.memory.read(info.typeInfoAddress + 2 * pointerSize + 4,
                                 &count, sizeof(count)) || count > 64)
            continue;
        uint64_t at = info.typeInfoAddress + 2 * pointerSize + 8;
        for (uint32_t index = 0; index < count; ++index) {
            uint64_t type = 0, offsetFlags = 0;
            if (!readPointer(program, at, pointerSize, type) ||
                !readPointer(program, at + pointerSize, pointerSize, offsetFlags))
                break;
            at += 2 * pointerSize;
            if (!typeInfoIndex.count(type)) continue;
            const CppClassInfo& base = result.classes[typeInfoIndex[type]];
            const bool isVirtual = (offsetFlags & 1U) != 0;
            const int64_t offset = static_cast<int64_t>(offsetFlags) >> 8;
            info.bases.push_back({base.name, type, offset, isVirtual});
        }
        (void)flags;
    }

    for (CppClassInfo& info : result.classes)
        for (CppVtableGroup& group : info.vtableGroups) {
            if (!group.offsetToTop) {
                group.baseSubobject = info.name;
                continue;
            }
            const int64_t subobjectOffset = -group.offsetToTop;
            const auto base = std::find_if(
                info.bases.begin(), info.bases.end(),
                [&](const CppBaseClass& candidate) {
                    return candidate.byteOffset == subobjectOffset;
                });
            if (base != info.bases.end()) group.baseSubobject = base->name;
        }

    std::sort(result.classes.begin(), result.classes.end(),
              [](const CppClassInfo& left, const CppClassInfo& right) {
                  return left.name < right.name;
              });
    return result;
}

void refineCppObjectGraph(const Program& program, const SleighEngine& engine,
                          const ProgramAnalysis& analysis,
                          CppRecoveryResult& recovery) {
    const int pointerSize = program.format == "ELF32" || program.format == "PE32"
                                ? 4 : 8;
    // Both x86-64 C++ ABIs appear in the wild: MSVC PE images pass `this`
    // in rcx, Itanium ELF and mingw PE images in rdi.  rdx is seeded as
    // well so a compiler shuffle of the object pointer into the second
    // argument register before the first dereference still tracks (the
    // synthetic recovery fixtures model `this` at offset 8).  Seeding is
    // only a heuristic root: detection further requires a vptr-shaped
    // dereference chain and resolution is gated by class/slot evidence.
    std::vector<uint64_t> abiThisRegisters = {0, 8, 56};
    if (program.arch != "x86-64") {
        abiThisRegisters = {program.format.rfind("PE", 0) == 0 ? uint64_t(0) : uint64_t(56)};
    }
    auto isThisRegister = [&](uint64_t offset) {
        return std::find(abiThisRegisters.begin(), abiThisRegisters.end(),
                         offset) != abiThisRegisters.end();
    };
    std::map<std::string, size_t> classIndex;
    for (size_t index = 0; index < recovery.classes.size(); ++index)
        classIndex.emplace(recovery.classes[index].name, index);
    auto ensureClass = [&](const std::string& name, CppAbi abi) -> size_t {
        const auto found = classIndex.find(name);
        if (found != classIndex.end()) return found->second;
        CppClassInfo info;
        info.name = name;
        info.abi = abi;
        info.stableIdentity = (abi == CppAbi::ITANIUM ? "itanium:" : "msvc:") +
                              name;
        info.templateInfo = templateInfo(name);
        info.libraryPattern = standardLibraryPattern(
            info.templateInfo.isInstantiation ? info.templateInfo.primaryName
                                               : info.name);
        const size_t index = recovery.classes.size();
        recovery.classes.push_back(std::move(info));
        classIndex[name] = index;
        return index;
    };

    std::map<uint64_t, std::pair<size_t, int64_t>> vtableClasses;
    for (size_t index = 0; index < recovery.classes.size(); ++index) {
        const CppClassInfo& info = recovery.classes[index];
        if (info.vtableAddress)
            vtableClasses[info.vtableAddress] = {index, 0};
        for (const CppVtableGroup& group : info.vtableGroups)
            vtableClasses[group.address] = {index, -group.offsetToTop};
    }

    std::map<uint64_t, size_t> graphMethod;
    for (const auto& pair : analysis.functions()) {
        const AnalyzedFunction& function = pair.second;
        const auto member = visibleMemberName(function.function.name);
        CppMethodInfo method;
        method.address = function.function.addr;
        method.name = function.function.name;
        method.role = symbolMethodRole(function.function.name,
                                       member.first, member.second);
        method.thisRegister = abiThisRegisters.front();
        method.thisAdjustment = itaniumThisAdjustment(function.function.name);
        method.hasThis = !member.first.empty();
        method.confidence = method.hasThis ? 0.92 : 0.25;
        if (method.hasThis) {
            const CppAbi abi = program.format.rfind("PE", 0) == 0
                                   ? CppAbi::MSVC : CppAbi::ITANIUM;
            const size_t owner = ensureClass(member.first, abi);
            recovery.objectGraph.functionClasses[method.address] = member.first;
            method.evidence.push_back({CppEvidenceKind::SYMBOL, method.address,
                method.address, 0.92, "member-function symbol establishes class ownership"});
            recovery.classes[owner].confidence =
                std::max(recovery.classes[owner].confidence, 0.75);
        }
        if (method.role == CppMethodRole::ADJUSTOR_THUNK ||
            method.role == CppMethodRole::COVARIANT_RETURN_THUNK)
            method.evidence.push_back({CppEvidenceKind::THUNK, method.address,
                method.address, 0.95, "ABI thunk mangling"});
        graphMethod[method.address] = recovery.objectGraph.methods.size();
        recovery.objectGraph.methods.push_back(std::move(method));
    }

    struct FieldObservation {
        int64_t offset = 0;
        uint64_t size = 0;
        bool write = false;
        uint64_t address = 0;
    };
    struct FunctionRefinement {
        uint64_t start = 0;
        std::string className;
        std::vector<FieldObservation> fields;
        std::vector<CppVptrWrite> vptrWrites;
        std::vector<CppEvidence> evidence;
        std::vector<CppVirtualCallSite> virtualCalls;
        bool constructorEvidence = false;
    };
    std::map<uint64_t, std::vector<FieldObservation>> fieldsByFunction;
    auto read = [&](uint64_t address, void* output, size_t size) {
        return program.memory.read(address, output, size);
    };
    auto executable = [&](uint64_t address) {
        return program.memory.isExecutable(address);
    };

    // CFG reconstruction dominates C++ object recovery for large programs.
    // Each function is independent at this stage, so workers produce private
    // result slots and the owning thread merges them in address order.  This
    // keeps recovery deterministic and avoids synchronizing the object graph.
    std::vector<const AnalyzedFunction*> refinementCandidates;
    refinementCandidates.reserve(analysis.functions().size());
    for (const auto& pair : analysis.functions())
        if (pair.second.complete)
            refinementCandidates.push_back(&pair.second);
    std::vector<FunctionRefinement> refinements(refinementCandidates.size());
    const std::map<uint64_t, std::string> initialFunctionClasses =
        recovery.objectGraph.functionClasses;

    size_t workerCount = std::max<size_t>(1, std::thread::hardware_concurrency());
    if (const char* configured = std::getenv("CENTRIFUGE_ANALYSIS_THREADS")) {
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(configured, &end, 10);
        if (end != configured && !*end && parsed)
            workerCount = static_cast<size_t>(parsed);
    }
    if (const char* configured = std::getenv("CENTRIFUGE_CPP_THREADS")) {
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(configured, &end, 10);
        if (end != configured && !*end && parsed)
            workerCount = static_cast<size_t>(parsed);
    }
    workerCount = std::min(workerCount, refinementCandidates.size());
    std::atomic<size_t> nextRefinement{0};
    auto refineWorker = [&]() {
        for (;;) {
            const size_t index = nextRefinement.fetch_add(1,
                std::memory_order_relaxed);
            if (index >= refinementCandidates.size()) break;
            const AnalyzedFunction& analyzed = *refinementCandidates[index];
            FunctionRefinement& refinement = refinements[index];
            const uint64_t start = analyzed.function.addr;
            refinement.start = start;
            const auto initialClass = initialFunctionClasses.find(start);
            if (initialClass != initialFunctionClasses.end())
                refinement.className = initialClass->second;
            const uint64_t end = analyzed.function.size &&
                start <= std::numeric_limits<uint64_t>::max() - analyzed.function.size
                    ? start + analyzed.function.size : 0;
            CfgBuilder cfg;
            if (!cfg.build(engine, read, start, end, executable)) continue;
            for (const CfgBlock& block : cfg.blocks()) {
            std::map<uint64_t, SymbolicObjectAddress> registers;
            SymbolicObjectAddress thisValue;
            thisValue.valid = true;
            thisValue.fromThis = true;
            for (const uint64_t tr : abiThisRegisters)
                registers[tr] = thisValue;
            for (const PcodeInsn& instruction : block.insns) {
                std::map<uint64_t, SymbolicObjectAddress> values;
                for (const auto& varnodePair : instruction.varnodes) {
                    const Varnode& varnode = varnodePair.second;
                    if (varnode.kind == Varnode::CONST) {
                        SymbolicObjectAddress value;
                        value.constant = true;
                        value.constantValue = varnode.offset;
                        values[varnode.id] = value;
                    } else if (varnode.kind == Varnode::REGISTER) {
                        const auto known = registers.find(varnode.offset);
                        if (known != registers.end()) values[varnode.id] = known->second;
                        else if (isThisRegister(varnode.offset)) values[varnode.id] = thisValue;
                    }
                }
                auto symbolic = [&](uint64_t id) {
                    const auto found = values.find(id);
                    return found == values.end() ? SymbolicObjectAddress{} : found->second;
                };
                for (const PcodeOp& operation : instruction.ops) {
                    SymbolicObjectAddress result;
                    const SymbolicObjectAddress left = symbolic(operation.in0);
                    const SymbolicObjectAddress right = symbolic(operation.in1);
                    if (operation.op == POp::COPY || operation.op == POp::INT_ZEXT ||
                        operation.op == POp::INT_SEXT || operation.op == POp::SUBPIECE) {
                        result = left;
                    } else if (operation.op == POp::INT_ADD ||
                               operation.op == POp::INT_SUB) {
                        const int direction = operation.op == POp::INT_SUB ? -1 : 1;
                        if (left.valid && right.constant) {
                            result = left;
                            result.offset += direction *
                                static_cast<int64_t>(right.constantValue);
                        } else if (operation.op == POp::INT_ADD &&
                                   right.valid && left.constant) {
                            result = right;
                            result.offset += static_cast<int64_t>(left.constantValue);
                        } else if (left.constant && right.constant) {
                            result.constant = true;
                            result.constantValue = operation.op == POp::INT_ADD
                                ? left.constantValue + right.constantValue
                                : left.constantValue - right.constantValue;
                        }
                    } else if (operation.op == POp::LOAD && left.valid) {
                        const Varnode* output = instruction.find(operation.out);
                        refinement.fields.push_back({left.offset,
                            static_cast<uint64_t>(output ? output->size : pointerSize),
                            false, instruction.addr});
                        result.valid = true;
                        result.fromThis = left.fromThis;
                        result.dereferenceDepth = left.dereferenceDepth + 1;
                        result.firstDereferenceOffset = left.dereferenceDepth
                            ? left.firstDereferenceOffset : left.offset;
                        result.lastDereferenceOffset = left.offset;
                    } else if (operation.op == POp::STORE && left.valid) {
                        const Varnode* stored = instruction.find(operation.in2);
                        refinement.fields.push_back({left.offset,
                            static_cast<uint64_t>(stored ? stored->size : pointerSize),
                            true, instruction.addr});
                        const SymbolicObjectAddress storedValue = symbolic(operation.in2);
                        if (storedValue.constant) {
                            const auto owner = vtableClasses.find(storedValue.constantValue);
                            if (owner != vtableClasses.end()) {
                                const std::string& className =
                                    recovery.classes[owner->second.first].name;
                                refinement.className = className;
                                refinement.vptrWrites.push_back({start,
                                    instruction.addr, className, left.offset,
                                    storedValue.constantValue, 0.98});
                                refinement.evidence.push_back({
                                    CppEvidenceKind::VPTR_STORE, instruction.addr,
                                    start, 0.98, "store of a known vtable address through this"});
                                refinement.constructorEvidence = true;
                            }
                        }
                    } else if ((operation.op == POp::CALLIND ||
                                operation.op == POp::BRANCHIND) &&
                               left.valid &&
                               // Double-load shape (`fn = load(vptr); call fn`)
                               // unambiguously names a slot.  The direct
                               // memory shape (`call [vptr+K]`, and the
                               // tail-dispatch `jmp [vptr+K]`) performs only
                               // one load before the transfer, so it must
                               // additionally root at the tracked object
                               // pointer and index a plausible vtable slot.
                               (left.dereferenceDepth >= 2 ||
                                (left.dereferenceDepth >= 1 && left.fromThis &&
                                 left.offset >= 0 && left.offset < 4096 &&
                                 left.offset % pointerSize == 0))) {
                        CppVirtualCallSite call;
                        call.functionAddress = start;
                        call.instructionAddress = instruction.addr;
                        call.vptrOffset = left.firstDereferenceOffset;
                        // The slot index is the displacement of the final
                        // address expression.  After a LOAD the tracked
                        // offset resets, so for the double-load shape the
                        // displacement recorded at the last load names the
                        // slot; for the direct memory shape the transfer's
                        // own input (vptr + K) carries it.
                        const int64_t slotOffset = left.dereferenceDepth >= 2
                            ? left.lastDereferenceOffset : left.offset;
                        call.slot = static_cast<size_t>(std::max<int64_t>(
                            0, slotOffset) / pointerSize);
                        call.className = refinement.className;
                        call.confidence = call.className.empty() ? 0.65 : 0.86;
                        refinement.virtualCalls.push_back(std::move(call));
                    }
                    if (operation.out) {
                        values[operation.out] = result;
                        const Varnode* output = instruction.find(operation.out);
                        if (output && output->kind == Varnode::REGISTER) {
                            if (result.valid || result.constant)
                                registers[output->offset] = result;
                            else registers.erase(output->offset);
                        }
                    }
                }
            }
        }
        }
    };
    std::vector<std::thread> workers;
    workers.reserve(workerCount);
    for (size_t index = 0; index < workerCount; ++index)
        workers.emplace_back(refineWorker);
    for (std::thread& worker : workers) worker.join();

    for (FunctionRefinement& refinement : refinements) {
        if (!refinement.fields.empty())
            fieldsByFunction.emplace(refinement.start,
                                     std::move(refinement.fields));
        if (!refinement.className.empty())
            recovery.objectGraph.functionClasses[refinement.start] =
                refinement.className;
        recovery.objectGraph.vptrWrites.insert(
            recovery.objectGraph.vptrWrites.end(),
            std::make_move_iterator(refinement.vptrWrites.begin()),
            std::make_move_iterator(refinement.vptrWrites.end()));
        recovery.objectGraph.evidence.insert(
            recovery.objectGraph.evidence.end(),
            std::make_move_iterator(refinement.evidence.begin()),
            std::make_move_iterator(refinement.evidence.end()));
        recovery.objectGraph.virtualCalls.insert(
            recovery.objectGraph.virtualCalls.end(),
            std::make_move_iterator(refinement.virtualCalls.begin()),
            std::make_move_iterator(refinement.virtualCalls.end()));
        if (refinement.constructorEvidence) {
            CppMethodInfo& method = recovery.objectGraph.methods[
                graphMethod.at(refinement.start)];
            method.hasThis = true;
            method.confidence = std::max(method.confidence, 0.98);
            if (method.role == CppMethodRole::UNKNOWN ||
                method.role == CppMethodRole::METHOD)
                method.role = CppMethodRole::CONSTRUCTOR;
        }
    }

    // Propagate a class identity into helper methods only when every known
    // caller agrees.  This avoids assigning generic utilities to the first
    // class that happens to call them.
    for (size_t pass = 0; pass < analysis.functions().size() + 1; ++pass) {
        bool changed = false;
        for (const auto& pair : analysis.functions()) {
            const uint64_t function = pair.first;
            if (recovery.objectGraph.functionClasses.count(function) ||
                pair.second.callers.empty()) continue;
            std::string common;
            bool agree = true;
            for (uint64_t caller : pair.second.callers) {
                const auto known = recovery.objectGraph.functionClasses.find(caller);
                if (known == recovery.objectGraph.functionClasses.end()) {
                    agree = false; break;
                }
                if (common.empty()) common = known->second;
                else if (common != known->second) { agree = false; break; }
            }
            if (!agree || common.empty()) continue;
            recovery.objectGraph.functionClasses[function] = common;
            CppMethodInfo& method = recovery.objectGraph.methods[graphMethod[function]];
            method.hasThis = true;
            method.thisRegister = abiThisRegisters.front();
            method.confidence = std::max(method.confidence, 0.68);
            method.evidence.push_back({CppEvidenceKind::THIS_FORWARD,
                function, function, 0.68,
                "all callers propagate the same class-owned this value"});
            changed = true;
        }
        if (!changed) break;
    }

    std::map<std::pair<std::string, int64_t>, size_t> fieldIndex;
    for (const auto& observations : fieldsByFunction) {
        const auto owner = recovery.objectGraph.functionClasses.find(observations.first);
        if (owner == recovery.objectGraph.functionClasses.end()) continue;
        const size_t classAt = ensureClass(owner->second,
            program.format.rfind("PE", 0) == 0 ? CppAbi::MSVC : CppAbi::ITANIUM);
        CppClassInfo& info = recovery.classes[classAt];
        for (const FieldObservation& observation : observations.second) {
            if (observation.offset < 0 || observation.offset > (1LL << 30)) continue;
            const auto key = std::make_pair(info.name, observation.offset);
            size_t index = 0;
            const auto found = fieldIndex.find(key);
            if (found == fieldIndex.end()) {
                CppFieldInfo field;
                field.byteOffset = observation.offset;
                field.byteSize = observation.size;
                field.name = observation.offset == 0 ? "vptr_or_field_0"
                    : "field_" + std::to_string(observation.offset);
                field.confidence = 0.62;
                index = info.fields.size();
                info.fields.push_back(std::move(field));
                fieldIndex[key] = index;
            } else index = found->second;
            CppFieldInfo& field = info.fields[index];
            field.byteSize = std::max(field.byteSize, observation.size);
            if (observation.write) ++field.writeCount;
            else ++field.readCount;
            field.confidence = std::min(0.96, field.confidence + 0.04);
            field.evidence.push_back({observation.write
                    ? CppEvidenceKind::FIELD_WRITE : CppEvidenceKind::FIELD_READ,
                observation.address, observations.first, 0.72,
                "this-relative memory access"});
        }
    }

    for (const CppVptrWrite& write : recovery.objectGraph.vptrWrites) {
        CppClassInfo& info = recovery.classes[classIndex[write.className]];
        auto field = std::find_if(info.fields.begin(), info.fields.end(),
            [&](const CppFieldInfo& candidate) {
                return candidate.byteOffset == write.objectOffset;
            });
        if (field == info.fields.end()) {
            CppFieldInfo vptr;
            vptr.byteOffset = write.objectOffset;
            vptr.byteSize = pointerSize;
            vptr.name = write.objectOffset ?
                "vptr_" + std::to_string(write.objectOffset) : "vptr";
            vptr.isVptr = true;
            vptr.typeName = "void**";
            vptr.confidence = write.confidence;
            info.fields.push_back(std::move(vptr));
        } else {
            field->isVptr = true;
            field->name = write.objectOffset ?
                "vptr_" + std::to_string(write.objectOffset) : "vptr";
            field->typeName = "void**";
            field->confidence = std::max(field->confidence, write.confidence);
        }
    }

    // Associate factories with classes when a function calls both an
    // allocator and a recovered constructor of that class.  Runtime helper
    // calls are recorded at the same time so later AST stages do not have to
    // rediscover dynamic_cast, typeid, throw/catch, or placement new.
    std::map<uint64_t, std::string> symbolNames;
    for (const Symbol& symbol : program.symbols)
        if (symbol.isFunction) symbolNames[symbol.addr] = symbol.name;
    for (const auto& pair : analysis.functions()) {
        bool allocates = false, placement = false, deallocates = false;
        std::set<std::string> constructedClasses;
        for (uint64_t callee : pair.second.callees) {
            const auto named = symbolNames.find(callee);
            const std::string name = named == symbolNames.end()
                                         ? std::string{} : named->second;
            allocates |= isAllocatorName(name);
            placement |= isPlacementAllocatorName(name);
            deallocates |= isDeallocatorName(name);
            if (const auto runtime = runtimeOperationKind(name)) {
                CppRuntimeOperation operation;
                operation.kind = *runtime;
                operation.functionAddress = pair.first;
                operation.instructionAddress = pair.first;
                const auto owner = recovery.objectGraph.functionClasses.find(pair.first);
                if (owner != recovery.objectGraph.functionClasses.end())
                    operation.className = owner->second;
                operation.confidence = 0.9;
                operation.evidence.push_back({
                    *runtime == CppRuntimeOperationKind::THROW_EXCEPTION ||
                            *runtime == CppRuntimeOperationKind::BEGIN_CATCH ||
                            *runtime == CppRuntimeOperationKind::END_CATCH ||
                            *runtime == CppRuntimeOperationKind::RETHROW
                        ? CppEvidenceKind::EXCEPTION_TYPE
                        : (*runtime == CppRuntimeOperationKind::PLACEMENT_NEW
                               ? CppEvidenceKind::ALLOCATION
                               : CppEvidenceKind::RTTI),
                    callee, pair.first, 0.9,
                    "recognized C++ runtime helper " + name});
                recovery.objectGraph.runtimeOperations.push_back(
                    std::move(operation));
            }
            const auto graph = graphMethod.find(callee);
            if (graph != graphMethod.end()) {
                const CppMethodInfo& method = recovery.objectGraph.methods[graph->second];
                if (method.role == CppMethodRole::CONSTRUCTOR ||
                    method.role == CppMethodRole::COPY_CONSTRUCTOR ||
                    method.role == CppMethodRole::MOVE_CONSTRUCTOR) {
                    const auto owner = recovery.objectGraph.functionClasses.find(callee);
                    if (owner != recovery.objectGraph.functionClasses.end())
                        constructedClasses.insert(owner->second);
                }
            }
        }
        if (allocates && !constructedClasses.empty()) {
            CppMethodInfo& method = recovery.objectGraph.methods[graphMethod[pair.first]];
            method.role = CppMethodRole::FACTORY;
            method.confidence = std::max(method.confidence, 0.82);
            for (const std::string& className : constructedClasses) {
                CppObjectCandidate object;
                object.id = recovery.objectGraph.objects.size() + 1;
                object.className = className;
                object.allocationSite = pair.first;
                object.placementNew = placement;
                object.confidence = placement ? 0.9 : 0.82;
                object.lifetime.push_back({CppLifetimeEventKind::ALLOCATE,
                    pair.first, pair.first, object.confidence});
                object.evidence.push_back({CppEvidenceKind::ALLOCATION,
                    pair.first, pair.first, object.confidence,
                    placement ? "placement new followed by class construction"
                              : "allocator followed by class construction"});
                recovery.objectGraph.objects.push_back(std::move(object));
            }
        }
        if (deallocates) {
            CppMethodInfo& method = recovery.objectGraph.methods[graphMethod[pair.first]];
            if (method.role == CppMethodRole::COMPLETE_DESTRUCTOR)
                method.role = CppMethodRole::DELETING_DESTRUCTOR;
        }
    }

    // Exception metadata is preserved as typed recovery operations.  LSDA or
    // FuncInfo action numbers remain explicit when the loader cannot yet name
    // the catch type, which is safer than inventing a class identity.
    for (const ExceptionRegion& region : program.exceptionRegions) {
        for (const ExceptionRegion::Handler& handler : region.handlers) {
            CppRuntimeOperation operation;
            operation.kind = CppRuntimeOperationKind::BEGIN_CATCH;
            operation.functionAddress = region.start;
            operation.instructionAddress = handler.landingPad;
            operation.landingPad = handler.landingPad;
            operation.action = handler.action;
            operation.referencedType = handler.action
                ? "exception_action_" + std::to_string(handler.action)
                : "cleanup";
            const auto owner = recovery.objectGraph.functionClasses.find(region.start);
            if (owner != recovery.objectGraph.functionClasses.end())
                operation.className = owner->second;
            operation.confidence = handler.action ? 0.78 : 0.62;
            operation.evidence.push_back({CppEvidenceKind::EXCEPTION_TYPE,
                handler.landingPad, region.start, operation.confidence,
                region.kind == ExceptionRegion::DWARF_CFI
                    ? "DWARF FDE/LSDA landing pad and action"
                    : "Windows unwind language-handler action"});
            recovery.objectGraph.runtimeOperations.push_back(std::move(operation));
        }
    }

    // Resolve virtual targets through the recovered vtable group and annotate
    // the target method.  Multiple candidates are retained by the public IR
    // even though a class-specific site normally resolves to one slot.
    for (CppVirtualCallSite& call : recovery.objectGraph.virtualCalls) {
        auto classAt = classIndex.find(call.className);
        if (classAt == classIndex.end()) {
            // The calling function owns no vptr store (e.g. a free function
            // taking a base pointer), so no class identity was attributed.
            // Fall back to the vtable slot evidence itself: when exactly one
            // recovered class has a function pointer at this slot, that
            // target is the only possible dispatch.  Ambiguous or empty
            // candidate sets keep the call indirect - devirtualizing a
            // genuinely polymorphic site would be wrong.
            std::set<uint64_t> candidates;
            for (const CppClassInfo& info : recovery.classes) {
                for (const CppVtableGroup& group : info.vtableGroups) {
                    if (call.slot >= group.virtualFunctions.size()) continue;
                    const uint64_t address =
                        group.virtualFunctions[call.slot].address;
                    if (address) candidates.insert(address);
                }
            }
            if (candidates.size() != 1) continue;
            call.resolvedTarget = *candidates.begin();
            call.resolvedTargets.push_back(call.resolvedTarget);
            call.confidence = std::max(call.confidence, 0.78);
            recovery.objectGraph.evidence.push_back({CppEvidenceKind::VIRTUAL_CALL,
                call.instructionAddress, call.functionAddress, call.confidence,
                "unique vtable slot candidate resolves the indirect call"});
            continue;
        }
        CppClassInfo& info = recovery.classes[classAt->second];
        const CppVtableGroup* selected = nullptr;
        for (const CppVtableGroup& group : info.vtableGroups)
            if (-group.offsetToTop == call.vptrOffset) {
                selected = &group;
                break;
            }
        if (!selected && !info.vtableGroups.empty())
            selected = &info.vtableGroups.front();
        const std::vector<CppVirtualFunction>& functions = selected
            ? selected->virtualFunctions : info.virtualFunctions;
        if (call.slot >= functions.size()) continue;
        call.resolvedTarget = functions[call.slot].address;
        call.resolvedTargets.push_back(call.resolvedTarget);
        call.confidence = std::max(call.confidence, 0.94);
        const auto target = graphMethod.find(call.resolvedTarget);
        if (target != graphMethod.end()) {
            CppMethodInfo& method = recovery.objectGraph.methods[target->second];
            method.isVirtual = true;
            method.virtualSlot = call.slot;
            const bool pure = method.name.find("pure_virtual") != std::string::npos ||
                              method.name.find("_purecall") != std::string::npos;
            method.role = pure ? CppMethodRole::PURE_VIRTUAL
                               : CppMethodRole::VIRTUAL_METHOD;
            method.confidence = std::max(method.confidence, 0.96);
        }
        recovery.objectGraph.evidence.push_back({CppEvidenceKind::VIRTUAL_CALL,
            call.instructionAddress, call.functionAddress, call.confidence,
            "class vptr offset and vtable slot resolve the indirect call"});
    }

    // Make base-class subobjects and virtual inheritance explicit in the
    // object layout.  Virtual bases are marked without inventing a fixed byte
    // offset when the ABI stores a vbtable/vbase displacement instead.
    for (CppClassInfo& info : recovery.classes) {
        for (const CppBaseClass& base : info.bases) {
            info.hasVirtualInheritance |= base.isVirtual;
            if (base.isVirtual || base.byteOffset < 0) continue;
            auto field = std::find_if(info.fields.begin(), info.fields.end(),
                [&](const CppFieldInfo& candidate) {
                    return candidate.byteOffset == base.byteOffset;
                });
            if (field == info.fields.end()) {
                CppFieldInfo subobject;
                subobject.byteOffset = base.byteOffset;
                subobject.byteSize = pointerSize;
                subobject.name = "base_" + base.name;
                subobject.typeName = base.name;
                subobject.isBaseSubobject = true;
                subobject.confidence = 0.9;
                info.fields.push_back(std::move(subobject));
            } else {
                field->isBaseSubobject = true;
                field->confidence = std::max(field->confidence, 0.9);
            }
        }
    }

    // Attach finalized roles to classes and create construction/destruction
    // lifetime events only after factory/deallocator/virtual classification.
    for (CppMethodInfo& method : recovery.objectGraph.methods) {
        const auto owner = recovery.objectGraph.functionClasses.find(method.address);
        if (owner == recovery.objectGraph.functionClasses.end()) continue;
        CppClassInfo& info = recovery.classes[classIndex[owner->second]];
        info.methods.push_back(method);
        if (method.role == CppMethodRole::CONSTRUCTOR ||
            method.role == CppMethodRole::COPY_CONSTRUCTOR ||
            method.role == CppMethodRole::MOVE_CONSTRUCTOR ||
            method.role == CppMethodRole::COPY_ASSIGNMENT ||
            method.role == CppMethodRole::MOVE_ASSIGNMENT ||
            method.role == CppMethodRole::BASE_DESTRUCTOR ||
            method.role == CppMethodRole::COMPLETE_DESTRUCTOR ||
            method.role == CppMethodRole::DELETING_DESTRUCTOR) {
            CppObjectCandidate object;
            object.id = recovery.objectGraph.objects.size() + 1;
            object.className = info.name;
            object.inferredSize = info.inferredSize;
            object.confidence = method.confidence;
            const bool destructor = method.role == CppMethodRole::BASE_DESTRUCTOR ||
                method.role == CppMethodRole::COMPLETE_DESTRUCTOR ||
                method.role == CppMethodRole::DELETING_DESTRUCTOR;
            CppLifetimeEventKind event = destructor
                ? CppLifetimeEventKind::DESTROY
                : method.role == CppMethodRole::COPY_ASSIGNMENT ||
                          method.role == CppMethodRole::MOVE_ASSIGNMENT
                      ? CppLifetimeEventKind::ASSIGN
                : method.role == CppMethodRole::COPY_CONSTRUCTOR
                      ? CppLifetimeEventKind::COPY_CONSTRUCT
                      : method.role == CppMethodRole::MOVE_CONSTRUCTOR
                            ? CppLifetimeEventKind::MOVE_CONSTRUCT
                            : CppLifetimeEventKind::CONSTRUCT;
            object.lifetime.push_back({event, method.address,
                method.address, method.confidence});
            object.evidence.push_back({CppEvidenceKind::LIFETIME,
                method.address, method.address, method.confidence,
                destructor ? "destructor ends object lifetime"
                           : "constructor begins object lifetime"});
            recovery.objectGraph.objects.push_back(std::move(object));
        }
    }

    for (const Symbol& symbol : program.symbols) {
        if (symbol.isFunction) continue;
        if (symbol.name.rfind("??_8", 0) == 0) {
            const size_t end = symbol.name.find("@@", 4);
            const std::string className = end == std::string::npos
                ? symbol.name.substr(4) : symbol.name.substr(4, end - 4);
            if (!className.empty()) {
                const size_t owner = ensureClass(className, CppAbi::MSVC);
                recovery.classes[owner].hasVirtualInheritance = true;
                recovery.classes[owner].confidence = std::max(
                    recovery.classes[owner].confidence, 0.94);
                recovery.classes[owner].evidence.push_back({
                    CppEvidenceKind::VTABLE, symbol.addr, 0, 0.94,
                    "MSVC vbtable symbol establishes virtual inheritance"});
            }
            continue;
        }
        const auto member = visibleMemberName(symbol.name);
        if (member.first.empty()) continue;
        const size_t owner = ensureClass(member.first,
            program.format.rfind("PE", 0) == 0 ? CppAbi::MSVC : CppAbi::ITANIUM);
        if (symbol.name.find("::*") != std::string::npos ||
            symbol.name.find("member_ptr") != std::string::npos ||
            symbol.name.find("member pointer") != std::string::npos) {
            uint64_t function = 0, adjustment = 0;
            if (readPointer(program, symbol.addr, pointerSize, function) &&
                readPointer(program, symbol.addr + pointerSize, pointerSize,
                            adjustment)) {
                CppMemberPointerInfo pointer;
                pointer.address = symbol.addr;
                pointer.ownerClass = member.first;
                pointer.name = symbol.name;
                pointer.functionOrVtableOffset = static_cast<int64_t>(function);
                pointer.thisAdjustment = static_cast<int64_t>(adjustment);
                pointer.isVirtual = program.format.rfind("ELF", 0) == 0
                    ? (function & 1U) != 0
                    : (!program.memory.isExecutable(function) &&
                       function < (1ULL << 20));
                pointer.confidence = 0.88;
                recovery.objectGraph.memberPointers.push_back(std::move(pointer));
            }
        }
        auto& members = recovery.classes[owner].staticMembers;
        if (std::find(members.begin(), members.end(), symbol.name) == members.end())
            members.push_back(symbol.name);
    }

    for (CppClassInfo& info : recovery.classes) {
        uint64_t extent = 0, occupied = 0, alignment = 1;
        for (const CppFieldInfo& field : info.fields) {
            if (field.byteOffset < 0) continue;
            extent = std::max(extent,
                static_cast<uint64_t>(field.byteOffset) + field.byteSize);
            occupied += field.byteSize;
            alignment = std::max(alignment, naturalAlignment(field.byteSize));
        }
        for (const CppBaseClass& base : info.bases)
            if (base.byteOffset >= 0)
                extent = std::max(extent, static_cast<uint64_t>(base.byteOffset));
        info.inferredAlignment = alignment;
        info.inferredSize = extent ? ((extent + alignment - 1) / alignment) * alignment : 0;
        info.inferredPadding = info.inferredSize > occupied
            ? info.inferredSize - occupied : 0;
        info.isAbstract = std::any_of(info.virtualFunctions.begin(),
            info.virtualFunctions.end(), [](const CppVirtualFunction& function) {
                return function.name.find("pure_virtual") != std::string::npos ||
                       function.name.find("_purecall") != std::string::npos;
            });
        if (!info.methods.empty() || !info.fields.empty())
            info.confidence = std::max(info.confidence, 0.7);
        std::sort(info.fields.begin(), info.fields.end(),
            [](const CppFieldInfo& left, const CppFieldInfo& right) {
                return left.byteOffset < right.byteOffset;
            });
    }
    for (CppObjectCandidate& object : recovery.objectGraph.objects) {
        const auto owner = classIndex.find(object.className);
        if (owner != classIndex.end())
            object.inferredSize = recovery.classes[owner->second].inferredSize;
    }
}

CppRecoveryResult mergeCppRecoveryResults(
    const std::vector<CppRecoveryResult>& modules) {
    CppRecoveryResult merged;
    std::map<std::pair<CppAbi, std::string>, size_t> index;
    uint64_t nextObjectId = 1;
    auto appendUniqueFunctions = [](std::vector<CppVirtualFunction>& output,
                                    const std::vector<CppVirtualFunction>& input) {
        for (const CppVirtualFunction& function : input)
            if (std::none_of(output.begin(), output.end(),
                             [&](const CppVirtualFunction& existing) {
                                 return existing.slot == function.slot &&
                                        existing.address == function.address;
                             }))
                output.push_back(function);
    };
    for (const CppRecoveryResult& module : modules) {
        merged.diagnostics.insert(merged.diagnostics.end(),
                                  module.diagnostics.begin(),
                                  module.diagnostics.end());
        for (const CppClassInfo& incoming : module.classes) {
            const auto key = std::make_pair(incoming.abi, incoming.name);
            auto found = index.find(key);
            if (found == index.end()) {
                index[key] = merged.classes.size();
                merged.classes.push_back(incoming);
                continue;
            }
            CppClassInfo& destination = merged.classes[found->second];
            if (destination.stableIdentity.empty())
                destination.stableIdentity = incoming.stableIdentity;
            if (destination.libraryPattern.empty())
                destination.libraryPattern = incoming.libraryPattern;
            if (!destination.typeInfoAddress)
                destination.typeInfoAddress = incoming.typeInfoAddress;
            if (!destination.vtableAddress)
                destination.vtableAddress = incoming.vtableAddress;
            if (!destination.templateInfo.isInstantiation)
                destination.templateInfo = incoming.templateInfo;
            appendUniqueFunctions(destination.virtualFunctions,
                                  incoming.virtualFunctions);
            for (const CppBaseClass& base : incoming.bases)
                if (std::none_of(destination.bases.begin(),
                                 destination.bases.end(),
                                 [&](const CppBaseClass& existing) {
                                     return existing.name == base.name &&
                                            existing.byteOffset == base.byteOffset;
                                 }))
                    destination.bases.push_back(base);
            for (const CppVtableGroup& group : incoming.vtableGroups)
                if (std::none_of(destination.vtableGroups.begin(),
                                 destination.vtableGroups.end(),
                                 [&](const CppVtableGroup& existing) {
                                     return existing.address == group.address &&
                                            existing.offsetToTop == group.offsetToTop;
                                 }))
                    destination.vtableGroups.push_back(group);
            for (const CppFieldInfo& field : incoming.fields) {
                const auto existing = std::find_if(destination.fields.begin(),
                    destination.fields.end(), [&](const CppFieldInfo& candidate) {
                        return candidate.byteOffset == field.byteOffset;
                    });
                if (existing == destination.fields.end()) {
                    destination.fields.push_back(field);
                } else {
                    existing->byteSize = std::max(existing->byteSize, field.byteSize);
                    existing->readCount += field.readCount;
                    existing->writeCount += field.writeCount;
                    existing->isVptr |= field.isVptr;
                    existing->isVbptr |= field.isVbptr;
                    existing->isBaseSubobject |= field.isBaseSubobject;
                    if (existing->name.empty()) existing->name = field.name;
                    if (existing->typeName.empty())
                        existing->typeName = field.typeName;
                    existing->confidence = std::max(existing->confidence,
                                                     field.confidence);
                    existing->evidence.insert(existing->evidence.end(),
                                              field.evidence.begin(),
                                              field.evidence.end());
                }
            }
            for (const CppMethodInfo& method : incoming.methods)
                if (std::none_of(destination.methods.begin(),
                                 destination.methods.end(),
                                 [&](const CppMethodInfo& existing) {
                                     return existing.address == method.address;
                                 }))
                    destination.methods.push_back(method);
            for (const std::string& member : incoming.staticMembers)
                if (std::find(destination.staticMembers.begin(),
                              destination.staticMembers.end(), member) ==
                    destination.staticMembers.end())
                    destination.staticMembers.push_back(member);
            destination.inferredSize = std::max(destination.inferredSize,
                                                incoming.inferredSize);
            destination.inferredAlignment = std::max(destination.inferredAlignment,
                                                     incoming.inferredAlignment);
            destination.inferredPadding = std::max(destination.inferredPadding,
                                                   incoming.inferredPadding);
            destination.isAbstract |= incoming.isAbstract;
            destination.hasVirtualInheritance |= incoming.hasVirtualInheritance;
            for (int64_t offset : incoming.vbptrOffsets)
                if (std::find(destination.vbptrOffsets.begin(),
                              destination.vbptrOffsets.end(), offset) ==
                    destination.vbptrOffsets.end())
                    destination.vbptrOffsets.push_back(offset);
            destination.confidence = std::max(destination.confidence,
                                              incoming.confidence);
            destination.evidence.insert(destination.evidence.end(),
                                        incoming.evidence.begin(),
                                        incoming.evidence.end());
            destination.evidence.push_back({CppEvidenceKind::CROSS_MODULE,
                incoming.typeInfoAddress ? incoming.typeInfoAddress
                                         : incoming.vtableAddress,
                0, 0.9, "class identity merged across module boundary"});
        }
        for (const CppMethodInfo& method : module.objectGraph.methods)
            if (std::none_of(merged.objectGraph.methods.begin(),
                             merged.objectGraph.methods.end(),
                             [&](const CppMethodInfo& existing) {
                                 return existing.address == method.address &&
                                        existing.name == method.name;
                             }))
                merged.objectGraph.methods.push_back(method);
        for (CppObjectCandidate object : module.objectGraph.objects) {
            object.id = nextObjectId++;
            merged.objectGraph.objects.push_back(std::move(object));
        }
        merged.objectGraph.vptrWrites.insert(merged.objectGraph.vptrWrites.end(),
            module.objectGraph.vptrWrites.begin(), module.objectGraph.vptrWrites.end());
        merged.objectGraph.virtualCalls.insert(merged.objectGraph.virtualCalls.end(),
            module.objectGraph.virtualCalls.begin(), module.objectGraph.virtualCalls.end());
        merged.objectGraph.runtimeOperations.insert(
            merged.objectGraph.runtimeOperations.end(),
            module.objectGraph.runtimeOperations.begin(),
            module.objectGraph.runtimeOperations.end());
        merged.objectGraph.memberPointers.insert(
            merged.objectGraph.memberPointers.end(),
            module.objectGraph.memberPointers.begin(),
            module.objectGraph.memberPointers.end());
        merged.objectGraph.evidence.insert(merged.objectGraph.evidence.end(),
            module.objectGraph.evidence.begin(), module.objectGraph.evidence.end());
        for (const auto& identity : module.objectGraph.functionClasses)
            merged.objectGraph.functionClasses.emplace(identity);
    }
    std::sort(merged.classes.begin(), merged.classes.end(),
              [](const CppClassInfo& left, const CppClassInfo& right) {
                  return left.name < right.name;
              });
    return merged;
}

} // namespace centrifuge
