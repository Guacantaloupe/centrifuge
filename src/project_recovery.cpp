// centrifuge - recompilable C++ source-project recovery
#include "centrifuge/project_recovery.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <vector>

#include "centrifuge/decompile.hpp"
#include "centrifuge/ir.hpp"
#include "centrifuge/program_graph.hpp"
#include "centrifuge/import_prototype.hpp"
#include "centrifuge/sleigh.hpp"

namespace centrifuge {
namespace {

std::string safeIdentifier(const std::string& input,
                           const std::string& fallback) {
    std::string output;
    output.reserve(input.size() + 1);
    for (unsigned char character : input) {
        if (std::isalnum(character) || character == '_')
            output += static_cast<char>(character);
        else if (!output.empty() && output.back() != '_')
            output += '_';
    }
    while (!output.empty() && output.back() == '_') output.pop_back();
    if (output.empty()) output = fallback;
    if (std::isdigit(static_cast<unsigned char>(output.front())))
        output.insert(output.begin(), '_');
    static const std::set<std::string> keywords = {
        "alignas", "alignof", "and", "asm", "auto", "bool", "break",
        "case", "catch", "char", "class", "const", "constexpr", "continue",
        "default", "delete", "do", "double", "else", "enum", "explicit",
        "export", "extern", "false", "float", "for", "friend", "goto",
        "if", "inline", "int", "long", "namespace", "new", "noexcept",
        "not", "nullptr", "operator", "or", "private", "protected",
        "public", "register", "reinterpret_cast", "return", "short",
        "signed", "sizeof", "static", "struct", "switch", "template",
        "this", "throw", "true", "try", "typedef", "typename", "union",
        "unsigned", "using", "virtual", "void", "volatile", "while", "xor"
    };
    if (keywords.count(output)) output += "_recovered";
    return output;
}

std::string hexAddress(uint64_t address) {
    std::ostringstream output;
    output << std::hex << address;
    return output.str();
}

std::string jsonString(const std::string& input) {
    std::string output;
    for (char character : input) {
        if (character == '\\') output += "\\\\";
        else if (character == '"') output += "\\\"";
        else if (character == '\n') output += "\\n";
        else if (character == '\r') output += "\\r";
        else if (character == '\t') output += "\\t";
        else if (static_cast<unsigned char>(character) < 0x20) output += "?";
        else output += character;
    }
    return output;
}

DataType compilableType(const DataType& input) {
    switch (input.kind) {
    case TypeKind::VOID_TYPE: return {TypeKind::VOID_TYPE, 0, 1};
    case TypeKind::BOOL: return {TypeKind::BOOL, 1, 1};
    case TypeKind::FLOAT:
        return {TypeKind::FLOAT, input.bits <= 32 ? 32 : 64, 1};
    case TypeKind::SIGNED_INT:
        return {TypeKind::SIGNED_INT,
                input.bits == 8 || input.bits == 16 || input.bits == 32
                    ? input.bits : 64, 1};
    default:
        return {TypeKind::UNSIGNED_INT,
                input.bits == 8 || input.bits == 16 || input.bits == 32
                    ? input.bits : 64, 1};
    }
}

FunctionSignature compilableSignature(const FunctionSignature& input) {
    FunctionSignature output;
    output.returnType = compilableType(input.returnType);
    output.variadic = input.variadic;
    // Project emission deliberately lowers complex ABI returns to one
    // compilable scalar until the recovered aggregate definition is stable.
    // Do not retain the original multi-register marker: decompileTyped would
    // otherwise try to construct a struct that this normalized signature no
    // longer names.
    output.hiddenSret = false;
    for (size_t index = 0; index < input.parameters.size(); ++index) {
        FunctionParameter parameter = input.parameters[index];
        parameter.name = safeIdentifier(parameter.name,
                                        "arg" + std::to_string(index));
        parameter.type = compilableType(parameter.type);
        output.parameters.push_back(std::move(parameter));
    }
    return output;
}

std::string defaultReturn(const DataType& type) {
    if (type.kind == TypeKind::VOID_TYPE) return "    return;\n";
    if (type.kind == TypeKind::FLOAT) return "    return 0.0;\n";
    if (type.kind == TypeKind::BOOL) return "    return false;\n";
    return "    return 0;\n";
}

bool writeFile(const std::filesystem::path& path, const std::string& contents,
               std::string& error) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        error = "cannot create " + path.string();
        return false;
    }
    stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    if (!stream) {
        error = "cannot write " + path.string();
        return false;
    }
    return true;
}

bool writeBytes(const std::filesystem::path& path,
                const std::vector<uint8_t>& contents, std::string& error) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        error = "cannot create " + path.string();
        return false;
    }
    if (!contents.empty())
        stream.write(reinterpret_cast<const char*>(contents.data()),
                     static_cast<std::streamsize>(contents.size()));
    if (!stream) {
        error = "cannot write " + path.string();
        return false;
    }
    return true;
}

size_t countMarker(const std::string& text, const std::string& marker) {
    size_t count = 0;
    for (size_t at = 0; (at = text.find(marker, at)) != std::string::npos;
         at += marker.size())
        ++count;
    return count;
}

std::string lowercaseAscii(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::map<std::string, std::filesystem::path> discoverImportLibraries(
    const Program& program) {
    namespace fs = std::filesystem;
    std::set<std::string> wanted;
    for (const ImportSymbol& imported : program.imports)
        if (!imported.library.empty())
            wanted.insert(lowercaseAscii(imported.library));
    std::map<std::string, fs::path> discovered;
    if (wanted.empty() || program.path.empty()) return discovered;

    std::error_code ec;
    fs::path input = fs::absolute(fs::path(program.path), ec);
    if (ec) return discovered;
    const fs::path directory = input.parent_path();
    if (directory.empty() || !fs::is_directory(directory, ec) || ec)
        return discovered;

    fs::recursive_directory_iterator iterator(
        directory, fs::directory_options::skip_permission_denied, ec);
    const fs::recursive_directory_iterator end;
    while (iterator != end) {
        if (ec) {
            ec.clear();
            iterator.increment(ec);
            continue;
        }
        std::error_code entryError;
        if (iterator->is_regular_file(entryError) && !entryError) {
            const std::string filename =
                lowercaseAscii(iterator->path().filename().string());
            if (wanted.count(filename) && !discovered.count(filename))
                discovered.emplace(filename, fs::absolute(iterator->path()));
        }
        iterator.increment(ec);
    }
    return discovered;
}

} // namespace

bool recoverSourceProject(const Program& program, const SleighEngine& engine,
                          const ProgramAnalysis& analysis,
                          const ProjectRecoveryOptions& options,
                          ProjectRecoveryReport& report, std::string& error) {
    namespace fs = std::filesystem;
    report = {};
    error.clear();
    if (options.outputDirectory.empty()) {
        error = "project output directory is empty";
        return false;
    }
    const fs::path root = fs::absolute(fs::path(options.outputDirectory));
    const fs::path includeDirectory = root / "include";
    const fs::path sourceDirectory = root / "src";
    const fs::path dataDirectory = root / "data";
    const fs::path resourceDirectory = root / "resources";
    const fs::path dependencyDirectory = root / "dependencies";
    std::error_code filesystemError;
    fs::create_directories(includeDirectory, filesystemError);
    if (filesystemError) {
        error = "cannot create include directory: " + filesystemError.message();
        return false;
    }
    fs::create_directories(sourceDirectory, filesystemError);
    if (filesystemError) {
        error = "cannot create source directory: " + filesystemError.message();
        return false;
    }
    fs::create_directories(dataDirectory, filesystemError);
    if (filesystemError) {
        error = "cannot create data directory: " + filesystemError.message();
        return false;
    }
    fs::create_directories(resourceDirectory, filesystemError);
    if (filesystemError) {
        error = "cannot create resource directory: " + filesystemError.message();
        return false;
    }
    fs::create_directories(dependencyDirectory, filesystemError);
    if (filesystemError) {
        error = "cannot create dependency directory: " +
                filesystemError.message();
        return false;
    }

    // Resolve imported DLLs relative to the input executable once, while the
    // original loader layout is still available.  The generated project gets
    // a local copy for ordinary use and retains the absolute source path as a
    // fallback for DLLs with non-imported siblings or private dependencies.
    const std::map<std::string, fs::path> importLibraryPaths =
        discoverImportLibraries(program);
    std::set<std::string> copiedImportLibraries;
    for (const ImportSymbol& imported : program.imports) {
        const std::string key = lowercaseAscii(imported.library);
        const auto found = importLibraryPaths.find(key);
        if (found == importLibraryPaths.end() ||
            !copiedImportLibraries.insert(key).second)
            continue;
        filesystemError.clear();
        fs::copy_file(found->second, dependencyDirectory / imported.library,
                      fs::copy_options::overwrite_existing, filesystemError);
        if (filesystemError) {
            error = "cannot copy recovered DLL " + found->second.string() +
                    ": " + filesystemError.message();
            return false;
        }
    }

    report.discoveredFunctions = analysis.functions().size();
    report.importedLibraries = program.importedLibraries.size();
    report.importedSymbols = program.imports.size();
    report.dataRegions = program.dataRegions.size();
    report.imageRegions = program.memory.blocks().size();
    for (const MemoryBlock& block : program.memory.blocks()) {
        if (block.data.size() > std::numeric_limits<uint64_t>::max() -
                                    report.imageBytes) {
            error = "recovered image size overflow";
            return false;
        }
        report.imageBytes += block.data.size();
    }
    report.resources = program.resources.size();
    report.entryPoint = program.entryPoint;
    for (const auto& entry : analysis.functions())
        if (entry.second.complexityLimited)
            ++report.complexityLimitedFunctions;
    std::map<uint64_t, std::string> names;
    std::set<std::string> usedNames;
    for (const auto& entry : analysis.functions()) {
        std::string name = safeIdentifier(entry.second.function.name,
                                          "function_" + hexAddress(entry.first));
        if (!usedNames.insert(name).second) {
            name += "_at_" + hexAddress(entry.first);
            usedNames.insert(name);
        }
        names[entry.first] = std::move(name);
    }
    std::map<uint64_t, FunctionSignature> signatures;
    for (const auto& entry : analysis.functions())
        signatures[entry.first] = compilableSignature(entry.second.signature);
    std::vector<uint64_t> selectedFunctions;
    for (const auto& entry : analysis.functions()) {
        if (!entry.second.complete && !options.emitIncompleteStubs) continue;
        selectedFunctions.push_back(entry.first);
    }
    if (options.maximumFunctions &&
        selectedFunctions.size() > options.maximumFunctions) {
        const auto entry = std::find(selectedFunctions.begin(),
                                     selectedFunctions.end(),
                                     program.entryPoint);
        std::vector<uint64_t> bounded;
        const size_t ordinaryLimit = entry == selectedFunctions.end()
                                         ? options.maximumFunctions
                                         : options.maximumFunctions - 1;
        for (uint64_t address : selectedFunctions) {
            if (bounded.size() >= ordinaryLimit) break;
            if (address == program.entryPoint) continue;
            bounded.push_back(address);
        }
        if (entry != selectedFunctions.end()) bounded.push_back(*entry);
        selectedFunctions = std::move(bounded);
    }
    const std::set<uint64_t> selectedSet(selectedFunctions.begin(),
                                         selectedFunctions.end());
    report.entryPointRecovered = selectedSet.count(program.entryPoint) != 0;
    std::map<uint64_t, size_t> importByIat;
    for (size_t index = 0; index < program.imports.size(); ++index)
        importByIat.emplace(program.imports[index].iatAddress, index);
    // Phase 6: recover import prototypes from call-site evidence, seeded by
    // the CRT/Win32 knowledge table.  Declarations below use the recovered
    // shapes instead of the generic 8-argument form.
    ImportPrototypeRecovery importPrototypes;
    importPrototypes.aggregate(analysis, program);
    importPrototypes.applyKnownPrototypes();
    std::map<uint64_t, std::string> externalNames;
    for (const auto& entry : analysis.functions())
        for (uint64_t callee : entry.second.callees)
            if (!names.count(callee)) {
                const auto imported = importByIat.find(callee);
                if (imported == importByIat.end()) {
                    externalNames.emplace(callee,
                        "external_" + hexAddress(callee));
                } else {
                    const ImportSymbol& symbol = program.imports[imported->second];
                    const std::string api = symbol.byOrdinal
                        ? ("ordinal_" + std::to_string(symbol.ordinal))
                        : symbol.name;
                    externalNames.emplace(callee,
                        "import_" + safeIdentifier(symbol.library, "dll") + "_" +
                        safeIdentifier(api, "api") + "_iat_" + hexAddress(callee));
                }
            }

    std::ostringstream header;
    header << "// Generated by Centrifuge from " << program.path << "\n"
           << "#pragma once\n#include <cstdint>\n#include <cstddef>\n\n";
    for (uint64_t address : selectedFunctions)
        header << signatures[address].declaration(names[address]) << ";\n";
    for (const auto& external : externalNames)
        header << "std::uint64_t " << external.second
               << "(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, "
                  "std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);\n";
    if (!writeFile(includeDirectory / "recovered.hpp", header.str(), error))
        return false;

    std::ostringstream types;
    types << "// Evidence-backed class-layout shells generated by Centrifuge\n"
          << "#pragma once\n#include <array>\n#include <cstddef>\n#include <cstdint>\n\n"
          << "namespace recovered_types {\n";
    std::set<std::string> emittedClasses;
    for (const CppClassInfo& info : analysis.cppTypes().classes) {
        std::string name = safeIdentifier(info.name, "anonymous_class");
        if (!emittedClasses.insert(name).second)
            name += "_at_" + hexAddress(info.typeInfoAddress);
        const uint64_t size = std::max<uint64_t>(1, info.inferredSize);
        const uint64_t alignment = std::max<uint64_t>(1, info.inferredAlignment);
        types << "// " << info.name << ", confidence=" << std::fixed
              << std::setprecision(2) << info.confidence << "\n"
              << "struct alignas(" << alignment << ") " << name << " {\n"
              << "    std::array<std::byte, " << size << "> storage{};\n"
              << "};\nstatic_assert(sizeof(" << name << ") == " << size << ");\n\n";
    }
    types << "} // namespace recovered_types\n";
    if (!writeFile(includeDirectory / "recovered_types.hpp", types.str(), error))
        return false;

    auto read = [&](uint64_t address, void* output, size_t size) {
        return program.memory.read(address, output, size);
    };
    auto nameOf = [&](uint64_t address) {
        const auto known = names.find(address);
        if (known != names.end()) return known->second;
        auto existing = externalNames.find(address);
        if (existing != externalNames.end()) return existing->second;
        return std::string("external_") + hexAddress(address);
    };
    auto signatureOf = [&](uint64_t address)
        -> std::optional<FunctionSignature> {
        const auto found = signatures.find(address);
        if (found == signatures.end()) return std::nullopt;
        return found->second;
    };
    std::string emissionArchitecture = program.arch;
    if (program.arch.rfind("x86", 0) == 0 &&
        (options.callingConvention == "win64" ||
         options.callingConvention == "ms"))
        emissionArchitecture += "-win64";

    const size_t functionsPerSource = std::max<size_t>(1, options.functionsPerSource);
    std::vector<std::string> sourceFiles;
    std::ostringstream source;
    size_t inShard = 0, shard = 0;
    auto beginShard = [&]() {
        source.str({});
        source.clear();
        source << "// Generated by Centrifuge; evidence remains in knowledge_graph.json\n"
               << "#include \"recovered.hpp\"\n#include \"recovered_types.hpp\"\n"
               << "#include \"recovered_runtime.hpp\"\n"
               << "#include <cstdint>\n#include <cstddef>\n#include <cmath>\n\n";
        inShard = 0;
    };
    auto finishShard = [&]() {
        if (!inShard) return true;
        const std::string file = "recovered_" + std::to_string(shard++) + ".cpp";
        if (!writeFile(sourceDirectory / file, source.str(), error)) return false;
        sourceFiles.push_back("src/" + file);
        ++report.sourceFiles;
        beginShard();
        return true;
    };
    beginShard();
    for (uint64_t address : selectedFunctions) {
        const auto found = analysis.functions().find(address);
        if (found == analysis.functions().end()) continue;
        const auto& entry = *found;
        const AnalyzedFunction& analyzed = entry.second;
        if (inShard == functionsPerSource && !finishShard()) return false;
        if (analyzed.complete) {
            uint64_t end = 0;
            if (analyzed.function.size && entry.first <=
                    std::numeric_limits<uint64_t>::max() - analyzed.function.size)
                end = entry.first + analyzed.function.size;
            const std::string body = decompileTyped(
                engine, read, entry.first, end, emissionArchitecture,
                names[entry.first],
                signatures[entry.first], nameOf, signatureOf, true);
            source << body << "\n";
            report.unresolvedMarkers += countMarker(body, "UNIMPLEMENTED") +
                                        countMarker(body, "/* call ") +
                                        countMarker(body, "/* unknown */");
            ++report.decompiledFunctions;
        } else {
            source << signatures[entry.first].declaration(names[entry.first])
                   << " {\n" << defaultReturn(signatures[entry.first].returnType)
                   << "}\n\n";
            ++report.stubbedFunctions;
        }
        ++inShard;
        ++report.emittedFunctions;
    }
    if (!finishShard()) return false;

    std::ostringstream externals;
    externals << "// Imported targets resolve through the recovered PE IAT model.\n"
              << "#include \"recovered_metadata.hpp\"\n"
              << "#include \"recovered_runtime.hpp\"\n#include <cstdint>\n\n"
              << "using RecoveredExternal = std::uint64_t (*)(std::uint64_t, "
                 "std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, "
                 "std::uint64_t, std::uint64_t, std::uint64_t);\n";
    for (const auto& external : externalNames) {
        externals << "std::uint64_t " << external.second
                  << "(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, "
                     "std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, "
                     "std::uint64_t a6, std::uint64_t a7) {\n";
        const auto imported = importByIat.find(external.first);
        if (imported == importByIat.end()) {
            externals << "    (void)a0; (void)a1; (void)a2; (void)a3; "
                         "(void)a4; (void)a5; (void)a6; (void)a7;\n"
                      << "    return 0;\n";
        } else {
            const ImportSymbol& symbol = program.imports[imported->second];
            if (!symbol.byOrdinal &&
                symbol.name ==
                    "_register_thread_local_exe_atexit_callback") {
                externals << "    (void)a1; (void)a2; (void)a3; (void)a4; "
                             "(void)a5; (void)a6; (void)a7;\n"
                          << "    return recovered_register_tls_atexit(a0);\n";
            } else if (!symbol.byOrdinal &&
                       symbol.name == "_crt_atexit") {
                externals << "    (void)a1; (void)a2; (void)a3; (void)a4; "
                             "(void)a5; (void)a6; (void)a7;\n"
                          << "    return recovered_register_process_atexit(a0);\n";
            } else if (!symbol.byOrdinal &&
                       symbol.name == "_initialize_onexit_table") {
                externals << "    (void)a1; (void)a2; (void)a3; (void)a4; "
                             "(void)a5; (void)a6; (void)a7;\n"
                          << "    return recovered_initialize_onexit_table(a0);\n";
            } else if (!symbol.byOrdinal &&
                       symbol.name == "_register_onexit_function") {
                externals << "    (void)a2; (void)a3; (void)a4; (void)a5; "
                             "(void)a6; (void)a7;\n"
                          << "    return recovered_register_onexit_function(a0, a1);\n";
            } else if (!symbol.byOrdinal &&
                       (symbol.name == "_initterm" ||
                        symbol.name == "_initterm_e")) {
                externals << "    (void)a2; (void)a3; (void)a4; (void)a5; "
                             "(void)a6; (void)a7;\n"
                          << "    return recovered_run_crt_initializers(a0, a1, "
                          << (symbol.name == "_initterm_e" ? "true" : "false")
                          << ");\n";
            } else if (!symbol.byOrdinal &&
                       (symbol.name == "_cexit" ||
                        symbol.name == "_c_exit")) {
                externals << "    (void)a0; (void)a1; (void)a2; (void)a3; "
                             "(void)a4; (void)a5; (void)a6; (void)a7;\n";
                if (symbol.name == "_cexit")
                    externals << "    recovered_run_process_atexit();\n";
                externals << "    return 0;\n";
            } else if (!symbol.byOrdinal &&
                       (symbol.name == "exit" ||
                        symbol.name == "_exit" ||
                        symbol.name == "_Exit" ||
                        symbol.name == "quick_exit")) {
                externals << "    (void)a1; (void)a2; (void)a3; (void)a4; "
                             "(void)a5; (void)a6; (void)a7;\n";
                if (symbol.name == "exit")
                    externals << "    recovered_run_process_atexit();\n";
                externals << "    recovered_report_process_exit(a0);\n"
                          << "    auto function = reinterpret_cast<RecoveredExternal>("
                          << "resolve_recovered_import(" << imported->second << "));\n"
                          << "    return function ? function(a0, 0, 0, 0, 0, 0, 0, 0) : 0;\n";
            } else if (!symbol.byOrdinal && symbol.name == "malloc") {
                externals << "    (void)a1; (void)a2; (void)a3; (void)a4; "
                             "(void)a5; (void)a6; (void)a7;\n"
                          << "    return recovered_heap_malloc(a0);\n";
            } else if (!symbol.byOrdinal && symbol.name == "calloc") {
                externals << "    (void)a2; (void)a3; (void)a4; (void)a5; "
                             "(void)a6; (void)a7;\n"
                          << "    return recovered_heap_calloc(a0, a1);\n";
            } else if (!symbol.byOrdinal && symbol.name == "realloc") {
                externals << "    (void)a2; (void)a3; (void)a4; (void)a5; "
                             "(void)a6; (void)a7;\n"
                          << "    return recovered_heap_realloc(a0, a1);\n";
            } else if (!symbol.byOrdinal && symbol.name == "free") {
                externals << "    (void)a1; (void)a2; (void)a3; (void)a4; "
                             "(void)a5; (void)a6; (void)a7;\n"
                          << "    recovered_heap_free(a0); return 0;\n";
            } else {
                externals << "    auto function = reinterpret_cast<RecoveredExternal>("
                          << "resolve_recovered_import(" << imported->second << "));\n"
                          << "    return function ? function("
                             "recovered_external_argument(a0), "
                             "recovered_external_argument(a1), "
                             "recovered_external_argument(a2), "
                             "recovered_external_argument(a3), "
                             "recovered_external_argument(a4), "
                             "recovered_external_argument(a5), "
                             "recovered_external_argument(a6), "
                             "recovered_external_argument(a7)) : 0;\n";
            }
        }
        externals << "}\n";
    }
    if (!externalNames.empty()) {
        if (!writeFile(sourceDirectory / "external_stubs.cpp", externals.str(),
                       error)) return false;
        sourceFiles.push_back("src/external_stubs.cpp");
        ++report.sourceFiles;
    }

    // Preserve every non-executable PE section as an exact initialized byte
    // stream plus virtual-size metadata.  This keeps writable globals,
    // read-only constants, unwind tables and zero-filled tails distinct while
    // avoiding enormous hexadecimal C++ initializers.
    std::ofstream globalBlob(dataDirectory / "globals.bin",
                             std::ios::binary | std::ios::trunc);
    if (!globalBlob) {
        error = "cannot create " + (dataDirectory / "globals.bin").string();
        return false;
    }
    uint64_t blobOffset = 0;
    std::vector<uint64_t> regionOffsets;
    std::ostringstream globalsJson;
    globalsJson << "{\n  \"schema\": 1,\n  \"blob\": \"data/globals.bin\","
                << "\n  \"regions\": [\n";
    for (size_t index = 0; index < program.dataRegions.size(); ++index) {
        const DataRegion& region = program.dataRegions[index];
        regionOffsets.push_back(blobOffset);
        const uint64_t initialized = std::min(region.size,
                                              region.initializedSize);
        uint64_t written = 0;
        std::vector<uint8_t> chunk;
        while (written < initialized) {
            const size_t amount = static_cast<size_t>(std::min<uint64_t>(
                initialized - written, 1024U * 1024U));
            chunk.resize(amount);
            if (region.address > std::numeric_limits<uint64_t>::max() - written ||
                !program.memory.read(region.address + written, chunk.data(), amount)) {
                error = "cannot read recovered data region " + region.name;
                return false;
            }
            globalBlob.write(reinterpret_cast<const char*>(chunk.data()),
                             static_cast<std::streamsize>(chunk.size()));
            if (!globalBlob) {
                error = "cannot write recovered global-data blob";
                return false;
            }
            written += amount;
        }
        globalsJson << "    {\"name\":\"" << jsonString(region.name)
                    << "\",\"address\":" << region.address
                    << ",\"virtual_size\":" << region.size
                    << ",\"initialized_size\":" << initialized
                    << ",\"blob_offset\":" << blobOffset
                    << ",\"permissions\":" << region.perm << "}"
                    << (index + 1 == program.dataRegions.size() ? "\n" : ",\n");
        if (initialized > std::numeric_limits<uint64_t>::max() - blobOffset) {
            error = "global-data blob size overflow";
            return false;
        }
        blobOffset += initialized;
    }
    globalBlob.close();
    globalsJson << "  ],\n  \"blob_size\": " << blobOffset << "\n}\n";
    if (!writeFile(root / "globals.json", globalsJson.str(), error)) return false;

    // Materialize the complete loader image, including PE headers and code.
    // The MSVC CRT reads the DOS/NT headers at ImageBase, while jump tables,
    // RTTI, unwind metadata, and embedded constants may live in executable
    // sections.  A globals-only runtime therefore cannot execute real startup.
    std::ofstream imageBlob(dataDirectory / "image.bin",
                            std::ios::binary | std::ios::trunc);
    if (!imageBlob) {
        error = "cannot create " + (dataDirectory / "image.bin").string();
        return false;
    }
    uint64_t imageBlobOffset = 0;
    std::vector<uint64_t> imageRegionOffsets;
    std::ostringstream imageJson;
    imageJson << "{\n  \"schema\": 1,\n  \"blob\": \"data/image.bin\"," 
              << "\n  \"regions\": [\n";
    const auto& imageBlocks = program.memory.blocks();
    for (size_t index = 0; index < imageBlocks.size(); ++index) {
        const MemoryBlock& block = imageBlocks[index];
        imageRegionOffsets.push_back(imageBlobOffset);
        if (!block.data.empty())
            imageBlob.write(reinterpret_cast<const char*>(block.data.data()),
                            static_cast<std::streamsize>(block.data.size()));
        if (!imageBlob) {
            error = "cannot write recovered image blob";
            return false;
        }
        imageJson << "    {\"name\":\"" << jsonString(block.name)
                  << "\",\"address\":" << block.base
                  << ",\"size\":" << block.data.size()
                  << ",\"blob_offset\":" << imageBlobOffset
                  << ",\"permissions\":" << block.perm << "}"
                  << (index + 1 == imageBlocks.size() ? "\n" : ",\n");
        imageBlobOffset += block.data.size();
    }
    imageBlob.close();
    imageJson << "  ],\n  \"blob_size\": " << imageBlobOffset << "\n}\n";
    if (!writeFile(root / "image.json", imageJson.str(), error)) return false;

    std::ostringstream importsJson;
    importsJson << "{\n  \"schema\": 1,\n  \"libraries\": [";
    for (size_t index = 0; index < program.importedLibraries.size(); ++index)
        importsJson << (index ? "," : "") << "\""
                    << jsonString(program.importedLibraries[index]) << "\"";
    importsJson << "],\n  \"symbols\": [\n";
    for (size_t index = 0; index < program.imports.size(); ++index) {
        const ImportSymbol& imported = program.imports[index];
        importsJson << "    {\"library\":\"" << jsonString(imported.library)
                    << "\",\"name\":\"" << jsonString(imported.name)
                    << "\",\"hint\":" << imported.hint
                    << ",\"ordinal\":" << imported.ordinal
                    << ",\"by_ordinal\":"
                    << (imported.byOrdinal ? "true" : "false")
                    << ",\"delayed\":"
                    << (imported.delayed ? "true" : "false")
                    << ",\"lookup_address\":" << imported.lookupAddress
                    << ",\"iat_address\":" << imported.iatAddress
                    << ",\"source_path\":\"";
        const auto sourcePath =
            importLibraryPaths.find(lowercaseAscii(imported.library));
        if (sourcePath != importLibraryPaths.end())
            importsJson << jsonString(sourcePath->second.string());
        importsJson << "\",\"bundled\":"
                    << (sourcePath != importLibraryPaths.end()
                            ? "true" : "false") << "}"
                    << (index + 1 == program.imports.size() ? "\n" : ",\n");
    }
    importsJson << "  ]\n}\n";
    if (!writeFile(root / "imports.json", importsJson.str(), error)) return false;

    std::vector<std::string> resourceFiles;
    std::ostringstream resourcesJson;
    resourcesJson << "{\n  \"schema\": 1,\n  \"resources\": [\n";
    for (size_t index = 0; index < program.resources.size(); ++index) {
        const ResourceEntry& resource = program.resources[index];
        std::ostringstream indexText;
        indexText << std::setw(5) << std::setfill('0') << index;
        const std::string type = resource.typeName.empty()
            ? std::to_string(resource.typeId) : resource.typeName;
        const std::string resourceName = resource.name.empty()
            ? std::to_string(resource.nameId) : resource.name;
        const std::string file = indexText.str() + "_" +
            safeIdentifier(type, "type") + "_" +
            safeIdentifier(resourceName, "resource") + "_" +
            std::to_string(resource.languageId) + ".bin";
        if (resource.size > std::numeric_limits<size_t>::max()) {
            error = "resource is too large to materialize";
            return false;
        }
        std::vector<uint8_t> bytes(resource.size);
        if (resource.size &&
            !program.memory.read(resource.dataAddress, bytes.data(), bytes.size())) {
            error = "cannot read PE resource at " +
                    std::to_string(resource.dataAddress);
            return false;
        }
        if (!writeBytes(resourceDirectory / file, bytes, error)) return false;
        resourceFiles.push_back("resources/" + file);
        resourcesJson << "    {\"type_id\":" << resource.typeId
                      << ",\"type_name\":\"" << jsonString(resource.typeName)
                      << "\",\"name_id\":" << resource.nameId
                      << ",\"name\":\"" << jsonString(resource.name)
                      << "\",\"language_id\":" << resource.languageId
                      << ",\"address\":" << resource.dataAddress
                      << ",\"size\":" << resource.size
                      << ",\"code_page\":" << resource.codePage
                      << ",\"file\":\"resources/" << jsonString(file) << "\"}"
                      << (index + 1 == program.resources.size() ? "\n" : ",\n");
    }
    resourcesJson << "  ]\n}\n";
    if (!writeFile(resourceDirectory / "index.json", resourcesJson.str(), error))
        return false;

    std::ostringstream entryJson;
    entryJson << "{\n  \"schema\": 1,\n  \"address\": " << program.entryPoint
              << ",\n  \"function\": \""
              << (report.entryPointRecovered ? jsonString(names[program.entryPoint]) : "")
              << "\",\n  \"recovered\": "
              << (report.entryPointRecovered ? "true" : "false") << "\n}\n";
    if (!writeFile(root / "entrypoint.json", entryJson.str(), error)) return false;

    // Compile loader metadata into the recovered library as well as emitting
    // JSON/binary artifacts.  On Windows callers can resolve each original
    // DLL binding lazily without hard-coding host-specific link directives.
    std::ostringstream metadataHeader;
    metadataHeader
        << "#pragma once\n#include <cstddef>\n#include <cstdint>\n\n"
        << "struct RecoveredImport { const char* library; const char* name; "
           "const char* source_path; std::uint16_t ordinal; std::uintptr_t iat; "
           "bool by_ordinal; bool delayed; };\n"
        << "struct RecoveredDataRegion { const char* name; std::uintptr_t address; "
           "std::uint64_t virtual_size; std::uint64_t initialized_size; "
           "std::uint64_t blob_offset; int permissions; };\n"
        << "struct RecoveredImageRegion { const char* name; std::uintptr_t address; "
           "std::uint64_t size; std::uint64_t blob_offset; int permissions; };\n"
        << "struct RecoveredResource { const char* type; const char* name; "
           "std::uint32_t language; std::uintptr_t address; std::uint32_t size; "
           "const char* file; };\n"
        << "extern const RecoveredImport recovered_imports[];\n"
        << "extern const std::size_t recovered_import_count;\n"
        << "extern const RecoveredDataRegion recovered_data_regions[];\n"
        << "extern const std::size_t recovered_data_region_count;\n"
        << "extern const RecoveredImageRegion recovered_image_regions[];\n"
        << "extern const std::size_t recovered_image_region_count;\n"
        << "extern const RecoveredResource recovered_resources[];\n"
        << "extern const std::size_t recovered_resource_count;\n"
        << "void* resolve_recovered_import(std::size_t index);\n"
        << "std::uintptr_t recovered_original_entry_point();\n"
        << "std::uint64_t recovered_invoke_entry();\n";
    if (!writeFile(includeDirectory / "recovered_metadata.hpp",
                   metadataHeader.str(), error)) return false;

    uint64_t firstIat = std::numeric_limits<uint64_t>::max();
    uint64_t lastIat = 0;
    for (const ImportSymbol& imported : program.imports) {
        if (!imported.iatAddress) continue;
        firstIat = std::min(firstIat, imported.iatAddress);
        lastIat = std::max(lastIat, imported.iatAddress);
    }
    if (firstIat == std::numeric_limits<uint64_t>::max()) firstIat = 1;

    std::ostringstream runtimeHeader;
    runtimeHeader
        << "#pragma once\n#include <algorithm>\n#include <array>\n#include <cstddef>\n#include <cstdint>\n#include <cstring>\n"
        << "#include <limits>\n\n"
        << "template <std::size_t Bytes> struct RecoveredVector {\n"
        << "    std::array<std::uint8_t, Bytes> bytes{};\n"
        << "    RecoveredVector(std::uint64_t low = 0) {\n"
        << "        std::memcpy(bytes.data(), &low, "
           "std::min(Bytes, sizeof(low)));\n"
        << "    }\n"
        << "    operator std::uint64_t() const {\n"
        << "        std::uint64_t low = 0;\n"
        << "        std::memcpy(&low, bytes.data(), "
           "std::min(Bytes, sizeof(low))); return low;\n"
        << "    }\n"
        << "};\n"
        << "using RecoveredVector128 = RecoveredVector<16>;\n"
        << "using RecoveredVector256 = RecoveredVector<32>;\n"
        << "using RecoveredVector512 = RecoveredVector<64>;\n\n"
        << "template <typename Lane, std::size_t Bytes>\n"
        << "Lane recovered_vector_extract(const RecoveredVector<Bytes>& vector, "
           "std::size_t lane) {\n"
        << "    Lane value{};\n"
        << "    if (lane < Bytes / sizeof(Lane))\n"
        << "        std::memcpy(&value, vector.bytes.data() + lane * sizeof(Lane), "
           "sizeof(Lane));\n"
        << "    return value;\n}\n\n"
        << "template <typename Lane, std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> recovered_vector_insert("
           "RecoveredVector<Bytes> vector, Lane value, std::size_t lane) {\n"
        << "    if (lane < Bytes / sizeof(Lane))\n"
        << "        std::memcpy(vector.bytes.data() + lane * sizeof(Lane), &value, "
           "sizeof(Lane));\n"
        << "    return vector;\n}\n\n"
        << "template <typename Scalar, std::size_t Bytes>\n"
        << "Scalar recovered_vector_scalar(const RecoveredVector<Bytes>& vector) {\n"
        << "    static_assert(sizeof(Scalar) <= Bytes, \"scalar lane exceeds vector\");\n"
        << "    Scalar value{};\n"
        << "    std::memcpy(&value, vector.bytes.data(), sizeof(Scalar));\n"
        << "    return value;\n}\n\n"
        << "template <typename Scalar, std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> recovered_vector_replace_scalar("
           "RecoveredVector<Bytes> vector, Scalar value) {\n"
        << "    static_assert(sizeof(Scalar) <= Bytes, \"scalar lane exceeds vector\");\n"
        << "    std::memcpy(vector.bytes.data(), &value, sizeof(Scalar));\n"
        << "    return vector;\n}\n\n"
        << "template <typename Scalar, typename Bits>\n"
        << "Scalar recovered_float_from_bits(Bits source) {\n"
        << "    std::uint64_t bits = static_cast<std::uint64_t>(source);\n"
        << "    Scalar value{};\n"
        << "    std::memcpy(&value, &bits, sizeof(Scalar));\n"
        << "    return value;\n}\n\n"
        << "// Lane-wise packed float arithmetic (addps/subps/mulps/divps\n"
        << "// and minps/maxps families).  Operates on the full byte\n"
        << "// array: each 32/64-bit lane of the destination is the\n"
        << "// corresponding lane of the two sources combined with the\n"
        << "// named operation.  The emitter names them simd_{op}_f32/f64.\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_add_f32(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 4; ++lane) {\n"
        << "        float x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 4, 4);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 4, 4);\n"
        << "        float z = x + y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 4, &z, 4);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_sub_f32(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 4; ++lane) {\n"
        << "        float x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 4, 4);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 4, 4);\n"
        << "        float z = x - y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 4, &z, 4);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_mul_f32(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 4; ++lane) {\n"
        << "        float x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 4, 4);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 4, 4);\n"
        << "        float z = x * y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 4, &z, 4);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_div_f32(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 4; ++lane) {\n"
        << "        float x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 4, 4);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 4, 4);\n"
        << "        float z = x / y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 4, &z, 4);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_min_f32(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 4; ++lane) {\n"
        << "        float x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 4, 4);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 4, 4);\n"
        << "        float z = std::min(x, y);\n"
        << "        std::memcpy(a.bytes.data() + lane * 4, &z, 4);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_max_f32(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 4; ++lane) {\n"
        << "        float x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 4, 4);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 4, 4);\n"
        << "        float z = std::max(x, y);\n"
        << "        std::memcpy(a.bytes.data() + lane * 4, &z, 4);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_add_f64(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 8; ++lane) {\n"
        << "        double x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 8, 8);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 8, 8);\n"
        << "        double z = x + y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 8, &z, 8);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_sub_f64(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 8; ++lane) {\n"
        << "        double x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 8, 8);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 8, 8);\n"
        << "        double z = x - y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 8, &z, 8);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_mul_f64(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 8; ++lane) {\n"
        << "        double x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 8, 8);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 8, 8);\n"
        << "        double z = x * y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 8, &z, 8);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_div_f64(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 8; ++lane) {\n"
        << "        double x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 8, 8);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 8, 8);\n"
        << "        double z = x / y;\n"
        << "        std::memcpy(a.bytes.data() + lane * 8, &z, 8);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_min_f64(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 8; ++lane) {\n"
        << "        double x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 8, 8);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 8, 8);\n"
        << "        double z = std::min(x, y);\n"
        << "        std::memcpy(a.bytes.data() + lane * 8, &z, 8);\n"
        << "    }\n    return a;\n}\n\n"
        << "template <std::size_t Bytes>\n"
        << "RecoveredVector<Bytes> simd_max_f64(RecoveredVector<Bytes> a, "
           "RecoveredVector<Bytes> b) {\n"
        << "    for (std::size_t lane = 0; lane < Bytes / 8; ++lane) {\n"
        << "        double x = 0, y = 0;\n"
        << "        std::memcpy(&x, a.bytes.data() + lane * 8, 8);\n"
        << "        std::memcpy(&y, b.bytes.data() + lane * 8, 8);\n"
        << "        double z = std::max(x, y);\n"
        << "        std::memcpy(a.bytes.data() + lane * 8, &z, 8);\n"
        << "    }\n    return a;\n}\n\n"
        << "bool recovered_runtime_initialize(const char* executable_or_root = nullptr);\n"
        << "void* recovered_translate_address(std::uintptr_t address, std::size_t size);\n"
        << "bool recovered_resolve_iat_slot(std::uintptr_t address, std::size_t size, "
           "std::uintptr_t& value);\n"
        << "inline constexpr std::uintptr_t recovered_iat_begin = "
        << firstIat << "ULL;\n"
        << "inline constexpr std::uintptr_t recovered_iat_end = "
        << lastIat << "ULL;\n"
        << "std::uintptr_t recovered_external_argument(std::uintptr_t value);\n"
        << "std::uint64_t recovered_runtime_fault_count();\n\n"
        << "std::uint64_t recovered_heap_malloc(std::uint64_t size);\n"
        << "std::uint64_t recovered_heap_calloc(std::uint64_t count, std::uint64_t size);\n"
        << "std::uint64_t recovered_heap_realloc(std::uint64_t address, std::uint64_t size);\n"
        << "void recovered_heap_free(std::uint64_t address);\n\n"
        << "std::uint64_t recovered_dispatch(std::uintptr_t address, "
           "std::uint64_t a0 = 0, std::uint64_t a1 = 0, "
           "std::uint64_t a2 = 0, std::uint64_t a3 = 0, "
           "std::uint64_t a4 = 0, std::uint64_t a5 = 0, "
           "std::uint64_t a6 = 0, std::uint64_t a7 = 0);\n"
        << "std::uint64_t recovered_unresolved_dispatch(std::uintptr_t address);\n"
        << "std::uint64_t recovered_dispatch_miss_count();\n"
        << "std::uint64_t recovered_run_crt_initializers("
           "std::uintptr_t first, std::uintptr_t last, bool returns_status);\n\n"
        << "void recovered_run_tls_callbacks();\n"
        << "std::uint64_t recovered_register_tls_atexit(std::uintptr_t callback);\n"
        << "std::size_t recovered_tls_atexit_callback_count();\n\n"
        << "std::uint64_t recovered_register_process_atexit(std::uintptr_t callback);\n"
        << "std::uint64_t recovered_initialize_onexit_table(std::uintptr_t table);\n"
        << "std::uint64_t recovered_register_onexit_function("
           "std::uintptr_t table, std::uintptr_t callback);\n"
        << "void recovered_run_process_atexit();\n"
        << "void recovered_report_process_exit(std::uint64_t code);\n\n"
        << "std::uintptr_t recovered_fs_base();\n"
        << "std::uintptr_t recovered_gs_base();\n\n"
        << "inline bool unsigned_mul_overflow(std::uint64_t left, "
           "std::uint64_t right) {\n"
        << "    return right != 0 && left > "
           "std::numeric_limits<std::uint64_t>::max() / right;\n}\n\n"
        << "inline bool signed_mul_overflow(std::uint64_t left, "
           "std::uint64_t right) {\n"
        << "    const auto a = static_cast<std::int64_t>(left);\n"
        << "    const auto b = static_cast<std::int64_t>(right);\n"
        << "    if (!a || !b) return false;\n"
        << "    const auto minimum = std::numeric_limits<std::int64_t>::min();\n"
        << "    const auto maximum = std::numeric_limits<std::int64_t>::max();\n"
        << "    if (a == -1) return b == minimum;\n"
        << "    if (b == -1) return a == minimum;\n"
        << "    if (a > 0) return b > 0 ? a > maximum / b : b < minimum / a;\n"
        << "    return b > 0 ? a < minimum / b : a < maximum / b;\n}\n\n"
        << "template <typename T> T recovered_load(std::uintptr_t address) {\n"
        << "    T value{};\n"
        << "    std::uintptr_t imported = 0;\n"
        << "    if constexpr (sizeof(T) == "
        << (program.format == "PE32" ? 4 : 8) << ") {\n"
        << "      if (address >= recovered_iat_begin && address <= recovered_iat_end &&\n"
        << "          recovered_resolve_iat_slot(address, sizeof(T), imported)) {\n"
        << "        std::memcpy(&value, &imported, "
           "std::min(sizeof(T), sizeof(imported)));\n"
        << "        return value;\n"
        << "      }\n"
        << "    }\n"
        << "    if (void* source = recovered_translate_address(address, sizeof(T)))\n"
        << "        std::memcpy(&value, source, sizeof(T));\n"
        << "    return value;\n}\n\n"
        << "template <typename T, typename U> void recovered_store("
           "std::uintptr_t address, U value) {\n"
        << "    const T converted = static_cast<T>(value);\n"
        << "    if (void* destination = recovered_translate_address(address, sizeof(T)))\n"
        << "        std::memcpy(destination, &converted, sizeof(T));\n"
        << "}\n\n"
        << "class RecoveredStackFrame {\npublic:\n"
        << "    RecoveredStackFrame();\n    ~RecoveredStackFrame();\n"
        << "    RecoveredStackFrame(const RecoveredStackFrame&) = delete;\n"
        << "    RecoveredStackFrame& operator=(const RecoveredStackFrame&) = delete;\n"
        << "    std::uintptr_t pointer() const { return pointer_; }\n"
        << "private:\n    std::size_t previous_ = 0;\n"
        << "    std::uintptr_t pointer_ = 0;\n};\n";
    if (!writeFile(includeDirectory / "recovered_runtime.hpp",
                   runtimeHeader.str(), error)) return false;

    uint64_t originalImageBegin = std::numeric_limits<uint64_t>::max();
    uint64_t originalImageEnd = 0;
    for (const MemoryBlock& block : program.memory.blocks()) {
        originalImageBegin = std::min(originalImageBegin, block.base);
        originalImageEnd = std::max(originalImageEnd, block.end());
    }
    if (program.memory.blocks().empty()) originalImageBegin = 0;
    uint64_t tlsRawStart = 0;
    uint64_t tlsRawSize = 0;
    uint64_t tlsIndexAddress = 0;
    uint64_t tlsZeroFillSize = 0;
    if (program.tls) {
        if (program.tls->rawDataEnd < program.tls->rawDataStart) {
            error = "invalid TLS template range";
            return false;
        }
        tlsRawStart = program.tls->rawDataStart;
        tlsRawSize = program.tls->rawDataEnd - program.tls->rawDataStart;
        tlsIndexAddress = program.tls->addressOfIndex;
        tlsZeroFillSize = program.tls->zeroFillSize;
        if (tlsRawSize > std::numeric_limits<size_t>::max() ||
            tlsZeroFillSize > std::numeric_limits<size_t>::max() - tlsRawSize) {
            error = "TLS template is too large for the host";
            return false;
        }
    }
    std::ostringstream runtime;
    runtime
        << "#include \"recovered_runtime.hpp\"\n"
        << "#include \"recovered_metadata.hpp\"\n"
        << "#include <algorithm>\n#include <array>\n#include <atomic>\n#include <filesystem>\n"
        << "#include <cstdio>\n#include <cstdlib>\n#include <fstream>\n#include <map>\n"
        << "#include <mutex>\n#include <vector>\n"
        << "#ifdef _WIN32\n#define WIN32_LEAN_AND_MEAN\n#include <windows.h>\n#endif\n\n"
        << "namespace {\n"
        << "struct RuntimeRegion { std::uintptr_t address = 0; "
           "std::vector<std::uint8_t> bytes; void* mapped = nullptr; };\n"
        << "std::vector<RuntimeRegion> runtime_regions;\n"
        << "void* runtime_fixed_image = nullptr;\n"
        << "std::map<std::uintptr_t, std::size_t> runtime_iat_slots;\n"
        << "std::mutex runtime_mutex;\n"
        << "std::atomic<bool> runtime_ready{false};\n"
        << "std::atomic<std::uint64_t> runtime_faults{0};\n"
        << "std::atomic<std::uint64_t> runtime_dispatch_misses{0};\n"
        << "std::mutex runtime_heap_mutex;\n"
        << "std::map<std::uintptr_t, std::size_t> runtime_heap_allocations;\n"
        << "bool runtime_strict_heap_bounds = false;\n"
        << "constexpr std::size_t heap_guard_bytes = 4096;\n"
        << "std::mutex runtime_exit_mutex;\n"
        << "std::vector<std::uintptr_t> runtime_process_atexit_callbacks;\n"
        << "std::map<std::uintptr_t, std::vector<std::uintptr_t>> "
           "runtime_onexit_tables;\n"
        << "std::vector<std::uintptr_t> runtime_first_dispatch_misses;\n"
        << "std::vector<std::uint8_t> runtime_tls_template;\n"
        << "std::once_flag runtime_tls_callback_once;\n"
        << "constexpr std::uintptr_t runtime_tls_raw_start = "
        << tlsRawStart << "ULL;\n"
        << "constexpr std::size_t runtime_tls_raw_size = "
        << tlsRawSize << "ULL;\n"
        << "constexpr std::size_t runtime_tls_zero_fill_size = "
        << tlsZeroFillSize << "ULL;\n"
        << "constexpr std::uintptr_t runtime_tls_index_address = "
        << tlsIndexAddress << "ULL;\n"
        << "constexpr std::uintptr_t original_image_begin = "
        << originalImageBegin << "ULL;\n"
        << "constexpr std::uintptr_t original_image_end = "
        << originalImageEnd << "ULL;\n"
        << "constexpr std::size_t stack_bytes = 64U * 1024U * 1024U;\n"
        << "constexpr std::size_t frame_bytes = 1024U * 1024U;\n"
        << "thread_local std::vector<std::uint8_t> runtime_stack(stack_bytes);\n"
        << "thread_local std::size_t runtime_stack_cursor = stack_bytes;\n"
        << "thread_local std::vector<std::uint8_t> runtime_teb(4096);\n"
        << "thread_local std::vector<std::uint8_t> runtime_tls_block;\n"
        << "thread_local std::array<std::uintptr_t, 1> runtime_tls_slots{};\n"
        << "thread_local bool runtime_tls_initialized = false;\n"
        << "thread_local std::vector<std::uintptr_t> runtime_tls_atexit_callbacks;\n"
        << "}\n\n"
        << "bool recovered_runtime_initialize(const char* executable_or_root) {\n"
        << "    if (runtime_ready.load(std::memory_order_acquire)) return true;\n"
        << "    std::lock_guard<std::mutex> guard(runtime_mutex);\n"
        << "    if (runtime_ready.load(std::memory_order_relaxed)) return true;\n"
#ifdef _WIN32
        << "    {\n"
        << "        // Warm the bcrypt RNG on the real OS stack.  First-use\n"
        << "        // crypto initialization runs deep inside delay-load\n"
        << "        // resolution and can overwrite the caller's frame on the\n"
        << "        // recovered stack layout (0xC0000409); warming it here\n"
        << "        // makes later ProcessPrng calls take the fast path.\n"
        << "        // Warm every RNG provider (advapi32 forwards to\n"
        << "        // bcrypt.dll; ntdll/bcrypt internals use\n"
        << "        // bcryptprimitives.dll - separate first-use state).\n"
        << "        for (const char* dll : {\"bcryptprimitives.dll\",\n"
        << "                                \"bcrypt.dll\",\n"
        << "                                \"advapi32.dll\"}) {\n"
        << "            HMODULE module = LoadLibraryA(dll);\n"
        << "            if (!module) continue;\n"
        << "            for (const char* symbol : {\"ProcessPrng\",\n"
        << "                                       \"SystemFunction036\"}) {\n"
        << "                const auto fn = reinterpret_cast<BOOLEAN(WINAPI*)(PVOID, ULONG)>(\n"
        << "                    GetProcAddress(module, symbol));\n"
        << "                if (!fn) continue;\n"
        << "                unsigned char seed[16];\n"
        << "                fn(seed, static_cast<ULONG>(sizeof(seed)));\n"
        << "            }\n"
        << "        }\n"
        << "    }\n"
#endif
        << "    namespace fs = std::filesystem;\n"
        << "    fs::path root = executable_or_root && *executable_or_root\n"
        << "        ? fs::absolute(fs::path(executable_or_root)) : fs::current_path();\n"
        << "    std::error_code ec;\n"
        << "    if (fs::is_regular_file(root, ec)) root = root.parent_path();\n"
        << "    fs::path blob = root / \"data\" / \"image.bin\";\n"
        << "    if (!fs::exists(blob, ec)) blob = fs::current_path() / \"data\" / \"image.bin\";\n"
        << "    std::ifstream input(blob, std::ios::binary);\n"
        << "    if (!input && recovered_image_region_count) return false;\n"
        << "    std::vector<RuntimeRegion> loaded;\n"
        << "    loaded.reserve(recovered_image_region_count);\n"
        << "    for (std::size_t index = 0; index < recovered_image_region_count; ++index) {\n"
        << "        const auto& descriptor = recovered_image_regions[index];\n"
        << "        if (descriptor.size > static_cast<std::uint64_t>(SIZE_MAX)) return false;\n"
        << "        RuntimeRegion region; region.address = descriptor.address;\n"
        << "        region.bytes.resize(static_cast<std::size_t>(descriptor.size), 0);\n"
        << "        input.seekg(static_cast<std::streamoff>(descriptor.blob_offset));\n"
        << "        if (descriptor.size)\n"
        << "            input.read(reinterpret_cast<char*>(region.bytes.data()),\n"
        << "                       static_cast<std::streamsize>(descriptor.size));\n"
        << "        if (!input && descriptor.size) return false;\n"
        << "        loaded.push_back(std::move(region));\n"
        << "    }\n"
        << "    runtime_tls_template.assign(runtime_tls_raw_size +\n"
        << "        runtime_tls_zero_fill_size, 0);\n"
        << "    if (runtime_tls_raw_size) {\n"
        << "        bool copied = false;\n"
        << "        for (const auto& region : loaded) {\n"
        << "            if (runtime_tls_raw_start < region.address) continue;\n"
        << "            const std::uint64_t offset = runtime_tls_raw_start - region.address;\n"
        << "            if (offset <= region.bytes.size() && runtime_tls_raw_size <=\n"
        << "                    region.bytes.size() - static_cast<std::size_t>(offset)) {\n"
        << "                std::memcpy(runtime_tls_template.data(),\n"
        << "                    region.bytes.data() + static_cast<std::size_t>(offset),\n"
        << "                    runtime_tls_raw_size);\n"
        << "                copied = true; break;\n"
        << "            }\n"
        << "        }\n"
        << "        if (!copied) return false;\n"
        << "    }\n"
        << "    if (runtime_tls_index_address) {\n"
        << "        bool initialized = false;\n"
        << "        for (auto& region : loaded) {\n"
        << "            if (runtime_tls_index_address < region.address) continue;\n"
        << "            const std::uint64_t offset = runtime_tls_index_address - region.address;\n"
        << "            if (offset <= region.bytes.size() && sizeof(std::uint32_t) <=\n"
        << "                    region.bytes.size() - static_cast<std::size_t>(offset)) {\n"
        << "                const std::uint32_t slot = 0;\n"
        << "                std::memcpy(region.bytes.data() + static_cast<std::size_t>(offset),\n"
        << "                    &slot, sizeof(slot));\n"
        << "                initialized = true; break;\n"
        << "            }\n"
        << "        }\n"
        << "        if (!initialized) return false;\n"
        << "    }\n"
        << "#ifdef _WIN32\n"
        << "    // Preserve the PE preferred virtual-address topology whenever the\n"
        << "    // range is available.  Top-level argument translation alone is not\n"
        << "    // enough for native DLL interoperability: C++ objects contain nested\n"
        << "    // vptr/vbtable/global pointers which host constructors dereference\n"
        << "    // directly.  Reserve the sparse span and commit only actual regions.\n"
        << "    if (original_image_begin >= 0x10000U &&\n"
        << "        original_image_end > original_image_begin) {\n"
        << "        SYSTEM_INFO systemInfo{}; GetSystemInfo(&systemInfo);\n"
        << "        const std::uintptr_t granularity = systemInfo.dwAllocationGranularity;\n"
        << "        const std::uintptr_t pageSize = systemInfo.dwPageSize;\n"
        << "        const std::uintptr_t reserveBegin =\n"
        << "            original_image_begin & ~(granularity - 1U);\n"
        << "        const std::uintptr_t reserveEnd =\n"
        << "            (original_image_end + granularity - 1U) & ~(granularity - 1U);\n"
        << "        if (reserveEnd > reserveBegin) {\n"
        << "            void* reservation = VirtualAlloc(\n"
        << "                reinterpret_cast<void*>(reserveBegin), reserveEnd - reserveBegin,\n"
        << "                MEM_RESERVE, PAGE_NOACCESS);\n"
        << "            bool mapped = reservation == reinterpret_cast<void*>(reserveBegin);\n"
        << "            for (auto& region : loaded) {\n"
        << "                if (!mapped || region.bytes.empty()) continue;\n"
        << "                const std::uintptr_t pageBegin =\n"
        << "                    region.address & ~(pageSize - 1U);\n"
        << "                const std::uintptr_t regionEnd =\n"
        << "                    region.address + region.bytes.size();\n"
        << "                const std::uintptr_t pageEnd =\n"
        << "                    (regionEnd + pageSize - 1U) & ~(pageSize - 1U);\n"
        << "                void* committed = VirtualAlloc(\n"
        << "                    reinterpret_cast<void*>(pageBegin), pageEnd - pageBegin,\n"
        << "                    MEM_COMMIT, PAGE_READWRITE);\n"
        << "                if (!committed) { mapped = false; break; }\n"
        << "            }\n"
        << "            if (mapped) {\n"
        << "                runtime_fixed_image = reservation;\n"
        << "                for (auto& region : loaded) {\n"
        << "                    if (!region.bytes.empty())\n"
        << "                        std::memcpy(reinterpret_cast<void*>(region.address),\n"
        << "                                    region.bytes.data(), region.bytes.size());\n"
        << "                    region.mapped = reinterpret_cast<void*>(region.address);\n"
        << "                }\n"
        << "            } else if (reservation) {\n"
        << "                VirtualFree(reservation, 0, MEM_RELEASE);\n"
        << "            }\n"
        << "        }\n"
        << "    }\n"
        << "#endif\n"
        << "    runtime_regions = std::move(loaded);\n"
        << "    runtime_iat_slots.clear();\n"
        << "    for (std::size_t index = 0; index < recovered_import_count; ++index)\n"
        << "        if (recovered_imports[index].iat)\n"
        << "            runtime_iat_slots.emplace(recovered_imports[index].iat, index);\n"
        << "    const char* strictHeap = std::getenv("
           "\"CENTRIFUGE_RUNTIME_STRICT_HEAP\");\n"
        << "    runtime_strict_heap_bounds = strictHeap && *strictHeap && "
           "std::strcmp(strictHeap, \"0\") != 0;\n"
        << "    runtime_ready.store(true, std::memory_order_release);\n"
        << "    return true;\n}\n\n"
        << "std::uint64_t recovered_heap_malloc(std::uint64_t requested) {\n"
        << "    if (requested > SIZE_MAX - heap_guard_bytes) { ++runtime_faults; return 0; }\n"
        << "    const std::size_t logical = static_cast<std::size_t>(requested);\n"
        << "    const std::size_t reserved = std::max<std::size_t>(logical, 1) + heap_guard_bytes;\n"
        << "    void* allocation = std::calloc(1, reserved);\n"
        << "    if (!allocation) return 0;\n"
        << "    const auto address = reinterpret_cast<std::uintptr_t>(allocation);\n"
        << "    { std::lock_guard<std::mutex> guard(runtime_heap_mutex);\n"
        << "      runtime_heap_allocations[address] = logical; }\n"
        << "    return static_cast<std::uint64_t>(address);\n}\n\n"
        << "std::uint64_t recovered_heap_calloc(std::uint64_t count, std::uint64_t size) {\n"
        << "    if (size && count > std::numeric_limits<std::uint64_t>::max() / size) "
           "{ ++runtime_faults; return 0; }\n"
        << "    return recovered_heap_malloc(count * size);\n}\n\n"
        << "void recovered_heap_free(std::uint64_t rawAddress) {\n"
        << "    if (!rawAddress) return;\n"
        << "    const auto address = static_cast<std::uintptr_t>(rawAddress);\n"
        << "    void* allocation = nullptr;\n"
        << "    { std::lock_guard<std::mutex> guard(runtime_heap_mutex);\n"
        << "      const auto found = runtime_heap_allocations.find(address);\n"
        << "      if (found == runtime_heap_allocations.end()) { ++runtime_faults; return; }\n"
        << "      allocation = reinterpret_cast<void*>(found->first);\n"
        << "      runtime_heap_allocations.erase(found); }\n"
        << "    std::free(allocation);\n}\n\n"
        << "std::uint64_t recovered_heap_realloc(std::uint64_t rawAddress, "
           "std::uint64_t requested) {\n"
        << "    if (!rawAddress) return recovered_heap_malloc(requested);\n"
        << "    if (!requested) { recovered_heap_free(rawAddress); return 0; }\n"
        << "    if (requested > SIZE_MAX - heap_guard_bytes) { ++runtime_faults; return 0; }\n"
        << "    const auto address = static_cast<std::uintptr_t>(rawAddress);\n"
        << "    std::lock_guard<std::mutex> guard(runtime_heap_mutex);\n"
        << "    const auto found = runtime_heap_allocations.find(address);\n"
        << "    if (found == runtime_heap_allocations.end()) { ++runtime_faults; return 0; }\n"
        << "    const std::size_t oldSize = found->second;\n"
        << "    const std::size_t logical = static_cast<std::size_t>(requested);\n"
        << "    void* resized = std::realloc(reinterpret_cast<void*>(address), "
           "logical + heap_guard_bytes);\n"
        << "    if (!resized) return 0;\n"
        << "    if (logical > oldSize) std::memset(static_cast<std::uint8_t*>(resized) + "
           "oldSize, 0, logical - oldSize + heap_guard_bytes);\n"
        << "    runtime_heap_allocations.erase(found);\n"
        << "    const auto resizedAddress = reinterpret_cast<std::uintptr_t>(resized);\n"
        << "    runtime_heap_allocations[resizedAddress] = logical;\n"
        << "    return static_cast<std::uint64_t>(resizedAddress);\n}\n\n"
        << "void* recovered_translate_address(std::uintptr_t address, std::size_t size) {\n"
        << "    if (!runtime_ready.load(std::memory_order_acquire) &&\n"
        << "        !recovered_runtime_initialize(nullptr)) { ++runtime_faults; return nullptr; }\n"
        << "    // Stack and heap addresses dominate recovered execution.  In fast\n"
        << "    // mode they are already native host pointers, so avoid scanning every\n"
        << "    // PE image region on each generated LOAD/STORE.\n"
        << "    if (!runtime_strict_heap_bounds &&\n"
        << "        (address < original_image_begin || address >= original_image_end)) {\n"
        << "        if (address < 0x10000U) { ++runtime_faults; return nullptr; }\n"
        << "        return reinterpret_cast<void*>(address);\n"
        << "    }\n"
        << "    for (auto& region : runtime_regions) {\n"
        << "        if (address < region.address) continue;\n"
        << "        const std::uint64_t offset = address - region.address;\n"
        << "        if (offset <= region.bytes.size() && size <= region.bytes.size() - offset)\n"
        << "            return region.mapped\n"
        << "                ? static_cast<std::uint8_t*>(region.mapped) +\n"
        << "                      static_cast<std::size_t>(offset)\n"
        << "                : region.bytes.data() + static_cast<std::size_t>(offset);\n"
        << "    }\n"
        << "    if (!runtime_strict_heap_bounds) {\n"
        << "        if (address >= original_image_begin && address < original_image_end) "
           "{ ++runtime_faults; return nullptr; }\n"
        << "        if (address < 0x10000U) { ++runtime_faults; return nullptr; }\n"
        << "        return reinterpret_cast<void*>(address);\n"
        << "    }\n"
        << "    { std::lock_guard<std::mutex> guard(runtime_heap_mutex);\n"
        << "      auto allocation = runtime_heap_allocations.upper_bound(address);\n"
        << "      if (allocation != runtime_heap_allocations.begin()) {\n"
        << "        --allocation; const std::uintptr_t base = allocation->first;\n"
        << "        const std::size_t logical = allocation->second;\n"
        << "        const std::uint64_t offset = address - base;\n"
        << "        if (address >= base && offset <= logical + heap_guard_bytes) {\n"
        << "          if (offset <= logical && size <= logical - static_cast<std::size_t>(offset))\n"
        << "            return reinterpret_cast<void*>(address);\n"
        << "          ++runtime_faults; return nullptr;\n"
        << "        }\n"
        << "      } }\n"
        << "    if (address >= original_image_begin && address < original_image_end) {\n"
        << "        ++runtime_faults; return nullptr;\n"
        << "    }\n"
        << "    if (address < 0x10000U) { ++runtime_faults; return nullptr; }\n"
        << "    return reinterpret_cast<void*>(address);\n}\n\n"
        << "bool recovered_resolve_iat_slot(std::uintptr_t address, std::size_t size, "
           "std::uintptr_t& value) {\n"
        << "    constexpr std::size_t recovered_pointer_bytes = "
        << (program.format == "PE32" ? 4 : 8) << ";\n"
        << "    if (size != recovered_pointer_bytes) return false;\n"
        << "    if (!runtime_ready.load(std::memory_order_acquire) &&\n"
        << "        !recovered_runtime_initialize(nullptr)) return false;\n"
        << "    if (runtime_iat_slots.empty() || "
           "address < runtime_iat_slots.begin()->first || "
           "address > runtime_iat_slots.rbegin()->first) return false;\n"
        << "    const auto slot = runtime_iat_slots.find(address);\n"
        << "    if (slot == runtime_iat_slots.end()) return false;\n"
        << "    void* resolved = resolve_recovered_import(slot->second);\n"
        << "    value = reinterpret_cast<std::uintptr_t>(resolved);\n"
        << "    if (!resolved) ++runtime_faults;\n"
        << "    return true;\n}\n\n"
        << "std::uintptr_t recovered_external_argument(std::uintptr_t value) {\n"
        << "    if (!runtime_ready.load(std::memory_order_acquire) &&\n"
        << "        !recovered_runtime_initialize(nullptr)) return value;\n"
        << "    if (value < original_image_begin || value >= original_image_end)\n"
        << "        return value;\n"
        << "    for (auto& region : runtime_regions) {\n"
        << "        if (value < region.address) continue;\n"
        << "        const std::uint64_t offset = value - region.address;\n"
        << "        if (offset < region.bytes.size())\n"
        << "            return reinterpret_cast<std::uintptr_t>(region.mapped\n"
        << "                ? static_cast<std::uint8_t*>(region.mapped) +\n"
        << "                      static_cast<std::size_t>(offset)\n"
        << "                : region.bytes.data() + static_cast<std::size_t>(offset));\n"
        << "    }\n"
        << "    return value;\n}\n\n"
        << "std::uint64_t recovered_runtime_fault_count() { return runtime_faults.load(); }\n\n"
        << "std::uint64_t recovered_unresolved_dispatch(std::uintptr_t address) {\n"
        << "    ++runtime_faults; ++runtime_dispatch_misses;\n"
        << "    { std::lock_guard<std::mutex> guard(runtime_exit_mutex);\n"
        << "      if (runtime_first_dispatch_misses.size() < 16)\n"
        << "          runtime_first_dispatch_misses.push_back(address); }\n"
        << "    return 0;\n}\n"
        << "std::uint64_t recovered_dispatch_miss_count() {\n"
        << "    return runtime_dispatch_misses.load();\n}\n"
        << "std::uint64_t recovered_run_crt_initializers(\n"
        << "    std::uintptr_t first, std::uintptr_t last, bool returns_status) {\n"
        << "    if (last < first || ((last - first) % sizeof(std::uintptr_t)) != 0 ||\n"
        << "        last - first > 16U * 1024U * 1024U) { ++runtime_faults; return 255; }\n"
        << "    for (std::uintptr_t cursor = first; cursor < last;\n"
        << "         cursor += sizeof(std::uintptr_t)) {\n"
        << "        const auto callback = recovered_load<std::uintptr_t>(cursor);\n"
        << "        if (!callback) continue;\n"
        << "        const std::uint64_t result = recovered_dispatch(callback);\n"
        << "        if (returns_status && result) return result;\n"
        << "    }\n"
        << "    return 0;\n}\n\n";
    runtime << "void recovered_run_tls_callbacks() {\n"
            << "    std::call_once(runtime_tls_callback_once, [] {\n";
    if (program.tls)
        for (uint64_t callback : program.tls->callbacks)
            runtime << "        recovered_dispatch(" << callback << "ULL, "
                    << program.imageBase << "ULL, 1, 0);\n";
    runtime << "    });\n}\n\n"
        << "std::uint64_t recovered_register_tls_atexit(std::uintptr_t callback) {\n"
        << "    if (!callback) { ++runtime_faults; return 1; }\n"
        << "    runtime_tls_atexit_callbacks.push_back(callback);\n"
        << "    return 0;\n}\n"
        << "std::size_t recovered_tls_atexit_callback_count() {\n"
        << "    return runtime_tls_atexit_callbacks.size();\n}\n\n"
        << "std::uint64_t recovered_register_process_atexit("
           "std::uintptr_t callback) {\n"
        << "    if (!callback) return 1;\n"
        << "    std::lock_guard<std::mutex> guard(runtime_exit_mutex);\n"
        << "    runtime_process_atexit_callbacks.push_back(callback); return 0;\n}\n"
        << "std::uint64_t recovered_initialize_onexit_table(std::uintptr_t table) {\n"
        << "    if (!table) return 1;\n"
        << "    std::lock_guard<std::mutex> guard(runtime_exit_mutex);\n"
        << "    runtime_onexit_tables[table].clear(); return 0;\n}\n"
        << "std::uint64_t recovered_register_onexit_function("
           "std::uintptr_t table, std::uintptr_t callback) {\n"
        << "    if (!table || !callback) return 1;\n"
        << "    std::lock_guard<std::mutex> guard(runtime_exit_mutex);\n"
        << "    runtime_onexit_tables[table].push_back(callback); return 0;\n}\n"
        << "void recovered_run_process_atexit() {\n"
        << "    std::vector<std::uintptr_t> callbacks;\n"
        << "    { std::lock_guard<std::mutex> guard(runtime_exit_mutex);\n"
        << "      callbacks.swap(runtime_process_atexit_callbacks);\n"
        << "      for (auto& table : runtime_onexit_tables)\n"
        << "          callbacks.insert(callbacks.end(), table.second.begin(), "
           "table.second.end());\n"
        << "      runtime_onexit_tables.clear(); }\n"
        << "    for (auto callback = callbacks.rbegin(); callback != callbacks.rend(); "
           "++callback) recovered_dispatch(*callback);\n"
        << "}\n"
        << "void recovered_report_process_exit(std::uint64_t code) {\n"
        << "    std::fprintf(stderr, \"recovered exit=%llu, runtime faults=%llu, "
           "dispatch misses=%llu\\n\",\n"
        << "        static_cast<unsigned long long>(code),\n"
        << "        static_cast<unsigned long long>(runtime_faults.load()),\n"
        << "        static_cast<unsigned long long>(runtime_dispatch_misses.load()));\n"
        << "    { std::lock_guard<std::mutex> guard(runtime_exit_mutex);\n"
        << "      if (!runtime_first_dispatch_misses.empty()) {\n"
        << "        std::fprintf(stderr, \"first missing recovered targets:\");\n"
        << "        for (std::uintptr_t address : runtime_first_dispatch_misses)\n"
        << "            std::fprintf(stderr, \" 0x%llx\", "
           "static_cast<unsigned long long>(address));\n"
        << "        std::fprintf(stderr, \"\\n\"); } }\n"
        << "    std::fflush(stderr);\n}\n\n"
        << "std::uintptr_t recovered_gs_base() {\n"
        << "    if (!runtime_ready.load(std::memory_order_acquire) &&\n"
        << "        !recovered_runtime_initialize(nullptr)) { ++runtime_faults; return 0; }\n"
        << "    if (!runtime_tls_initialized) {\n"
        << "        runtime_tls_block = runtime_tls_template;\n"
        << "        runtime_tls_slots[0] = runtime_tls_block.empty() ? 0 :\n"
        << "            reinterpret_cast<std::uintptr_t>(runtime_tls_block.data());\n"
        << "        const auto slots =\n"
        << "            reinterpret_cast<std::uintptr_t>(runtime_tls_slots.data());\n"
        << "        std::memcpy(runtime_teb.data() + 0x58, &slots, sizeof(slots));\n"
        << "        runtime_tls_initialized = true;\n"
        << "    }\n"
        << "    const auto base = reinterpret_cast<std::uintptr_t>(runtime_teb.data());\n"
        << "    std::memcpy(runtime_teb.data() + 0x30, &base, sizeof(base));\n"
        << "    return base;\n}\n"
        << "std::uintptr_t recovered_fs_base() { return recovered_gs_base(); }\n\n"
        << "RecoveredStackFrame::RecoveredStackFrame() {\n"
        << "    previous_ = runtime_stack_cursor;\n"
        << "    if (runtime_stack_cursor < frame_bytes) { ++runtime_faults; return; }\n"
        << "    runtime_stack_cursor -= frame_bytes;\n"
        << "    const auto top = reinterpret_cast<std::uintptr_t>("
           "runtime_stack.data() + previous_ - 4096);\n"
        << "    pointer_ = (top & ~static_cast<std::uintptr_t>(15)) - 8;\n"
        << "}\n"
        << "RecoveredStackFrame::~RecoveredStackFrame() { runtime_stack_cursor = previous_; }\n";
    if (!writeFile(sourceDirectory / "recovered_runtime.cpp", runtime.str(),
                   error)) return false;
    sourceFiles.push_back("src/recovered_runtime.cpp");
    ++report.sourceFiles;

    std::ostringstream metadata;
    metadata << "#include \"recovered_metadata.hpp\"\n#include \"recovered.hpp\"\n"
             << "#include \"recovered_runtime.hpp\"\n"
             << "#include <array>\n#include <atomic>\n#include <string>\n"
             << "#ifdef _WIN32\n#define WIN32_LEAN_AND_MEAN\n#include <windows.h>\n#endif\n\n";
    metadata << "const RecoveredImport recovered_imports[] = {\n";
    if (program.imports.empty()) metadata << "    {nullptr, nullptr, nullptr, 0, 0, false, false}\n";
    for (const ImportSymbol& imported : program.imports) {
        const auto sourcePath =
            importLibraryPaths.find(lowercaseAscii(imported.library));
        metadata << "    {\"" << jsonString(imported.library) << "\", \""
                 << jsonString(imported.name) << "\", \"";
        if (sourcePath != importLibraryPaths.end())
            metadata << jsonString(sourcePath->second.string());
        metadata << "\", " << imported.ordinal
                 << ", " << imported.iatAddress << "ULL, "
                 << (imported.byOrdinal ? "true" : "false") << ", "
                 << (imported.delayed ? "true" : "false") << "},\n";
    }
    metadata << "};\nconst std::size_t recovered_import_count = "
             << program.imports.size() << ";\n\n";
    metadata << "const RecoveredDataRegion recovered_data_regions[] = {\n";
    if (program.dataRegions.empty()) metadata << "    {nullptr, 0, 0, 0, 0, 0}\n";
    for (size_t index = 0; index < program.dataRegions.size(); ++index) {
        const DataRegion& region = program.dataRegions[index];
        metadata << "    {\"" << jsonString(region.name) << "\", "
                 << region.address << "ULL, " << region.size << "ULL, "
                 << std::min(region.size, region.initializedSize) << "ULL, "
                 << regionOffsets[index] << "ULL, " << region.perm << "},\n";
    }
    metadata << "};\nconst std::size_t recovered_data_region_count = "
             << program.dataRegions.size() << ";\n\n";
    metadata << "const RecoveredImageRegion recovered_image_regions[] = {\n";
    if (program.memory.blocks().empty())
        metadata << "    {nullptr, 0, 0, 0, 0}\n";
    for (size_t index = 0; index < program.memory.blocks().size(); ++index) {
        const MemoryBlock& block = program.memory.blocks()[index];
        metadata << "    {\"" << jsonString(block.name) << "\", "
                 << block.base << "ULL, " << block.data.size() << "ULL, "
                 << imageRegionOffsets[index] << "ULL, " << block.perm << "},\n";
    }
    metadata << "};\nconst std::size_t recovered_image_region_count = "
             << program.memory.blocks().size() << ";\n\n";
    metadata << "const RecoveredResource recovered_resources[] = {\n";
    if (program.resources.empty()) metadata << "    {nullptr, nullptr, 0, 0, 0, nullptr}\n";
    for (size_t index = 0; index < program.resources.size(); ++index) {
        const ResourceEntry& resource = program.resources[index];
        const std::string type = resource.typeName.empty()
            ? std::to_string(resource.typeId) : resource.typeName;
        const std::string resourceName = resource.name.empty()
            ? std::to_string(resource.nameId) : resource.name;
        metadata << "    {\"" << jsonString(type) << "\", \""
                 << jsonString(resourceName) << "\", " << resource.languageId
                 << ", " << resource.dataAddress << "ULL, " << resource.size
                 << ", \"" << jsonString(resourceFiles[index]) << "\"},\n";
    }
    metadata << "};\nconst std::size_t recovered_resource_count = "
             << program.resources.size() << ";\n\n"
             << "void* resolve_recovered_import(std::size_t index) {\n"
             << "    if (index >= recovered_import_count) return nullptr;\n"
             << "#ifdef _WIN32\n"
             << "    // Imports are immutable after first resolution.  A lock-free\n"
             << "    // per-slot cache avoids serializing every recovered libc call.\n"
             << "    static std::array<std::atomic<std::uintptr_t>, "
             << program.imports.size() << "> cache{};\n"
             << "    constexpr std::uintptr_t missing = 1;\n"
             << "    const std::uintptr_t cached = cache[index].load(std::memory_order_acquire);\n"
             << "    if (cached) return cached == missing ? nullptr : reinterpret_cast<void*>(cached);\n"
             << "    const auto& item = recovered_imports[index];\n"
             << "    HMODULE module = LoadLibraryA(item.library);\n"
             << "    if (!module) {\n"
             << "        char executable[MAX_PATH]{};\n"
             << "        const DWORD length = GetModuleFileNameA(nullptr, executable, MAX_PATH);\n"
             << "        if (length && length < MAX_PATH) {\n"
             << "            std::string bundled(executable, length);\n"
             << "            const auto separator = bundled.find_last_of(\"\\\\/\");\n"
             << "            bundled.resize(separator == std::string::npos ? 0 : separator + 1);\n"
             << "            bundled += \"dependencies\\\\\"; bundled += item.library;\n"
             << "            module = LoadLibraryExA(bundled.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);\n"
             << "        }\n"
             << "    }\n"
             << "    if (!module && item.source_path && *item.source_path)\n"
             << "        module = LoadLibraryExA(item.source_path, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);\n"
             << "    if (!module) { cache[index].store(missing, std::memory_order_release); return nullptr; }\n"
             << "    const char* symbol = item.by_ordinal\n"
             << "        ? reinterpret_cast<const char*>(static_cast<std::uintptr_t>(item.ordinal))\n"
             << "        : item.name;\n"
             << "    void* resolved = reinterpret_cast<void*>(GetProcAddress(module, symbol));\n"
             << "    std::uintptr_t value = resolved ? reinterpret_cast<std::uintptr_t>(resolved) : missing;\n"
             << "    std::uintptr_t expected = 0;\n"
             << "    if (!cache[index].compare_exchange_strong(expected, value,\n"
             << "            std::memory_order_release, std::memory_order_acquire))\n"
             << "        value = expected;\n"
             << "    return value == missing ? nullptr : reinterpret_cast<void*>(value);\n"
             << "#else\n    (void)index; return nullptr;\n#endif\n}\n\n"
             << "std::uintptr_t recovered_original_entry_point() { return "
             << program.entryPoint << "ULL; }\n";
    metadata << "std::uint64_t recovered_invoke_entry() {\n";
    metadata << "    if (!recovered_runtime_initialize(nullptr)) return 0;\n";
    metadata << "    recovered_run_tls_callbacks();\n";
    if (report.entryPointRecovered) {
        const FunctionSignature& signature = signatures[program.entryPoint];
        std::string arguments;
        for (size_t index = 0; index < signature.parameters.size(); ++index)
            arguments += (index ? ", " : "") + std::string("0");
        if (signature.returnType.kind == TypeKind::VOID_TYPE) {
            metadata << "    " << names[program.entryPoint] << "(" << arguments
                     << ");\n    return 0;\n";
        } else {
            metadata << "    return static_cast<std::uint64_t>("
                     << names[program.entryPoint] << "(" << arguments << "));\n";
        }
    } else {
        metadata << "    return 0;\n";
    }
    metadata << "}\n";
    metadata << "\nstd::uint64_t recovered_dispatch(std::uintptr_t address, "
             << "std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, "
                "std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, "
                "std::uint64_t a6, std::uint64_t a7) {\n"
             << "    switch (address) {\n";
    for (uint64_t address : selectedFunctions) {
        const FunctionSignature& signature = signatures[address];
        std::string arguments;
        for (size_t index = 0; index < signature.parameters.size(); ++index) {
            const std::string source = index < 8
                ? "a" + std::to_string(index) : "0";
            arguments += (index ? ", " : "") +
                std::string("static_cast<") +
                signature.parameters[index].type.name() + ">(" + source + ")";
        }
        metadata << "    case " << address << "ULL:\n        ";
        if (signature.returnType.kind == TypeKind::VOID_TYPE) {
            metadata << names[address] << "(" << arguments
                     << "); return 0;\n";
        } else {
            metadata << "return static_cast<std::uint64_t>("
                     << names[address] << "(" << arguments << "));\n";
        }
    }
    metadata << "    default: return recovered_unresolved_dispatch(address);\n"
             << "    }\n}\n";
    if (!writeFile(sourceDirectory / "recovered_metadata.cpp", metadata.str(),
                   error)) return false;
    sourceFiles.push_back("src/recovered_metadata.cpp");
    ++report.sourceFiles;

    const ProgramKnowledgeGraph graph =
        buildProgramKnowledgeGraph(program, analysis);
    report.knowledgeNodes = graph.nodes().size();
    report.knowledgeEdges = graph.edges().size();
    if (!writeFile(root / "knowledge_graph.json", graph.toJson(), error))
        return false;

    std::ostringstream mainSource;
    mainSource << "#include \"recovered_metadata.hpp\"\n"
               << "#include \"recovered_runtime.hpp\"\n"
               << "#include <cstring>\n#include <cstdlib>\n#include <iostream>\n"
               << "#ifdef _WIN32\n#include <windows.h>\n#endif\n"
               << "int main(int argc, char** argv) {\n"
               << "#ifdef _WIN32\n"
<< "    {\n"
<< "        // Warm every RNG provider before any delay-load import\n"
<< "        // resolution: advapi32 forwards to bcrypt.dll, ntdll/bcrypt\n"
<< "        // internals use bcryptprimitives.dll, and msvcrt rand_s\n"
<< "        // walks cryptbase.dll - each has separate first-use state.\n"
<< "        // Doing this on the shallow main stack keeps first-use\n"
<< "        // crypto initialization off the recovered stack layout\n"
<< "        // (0xC0000409 mitigation).\n"
<< "        for (const char* dll : {\"bcryptprimitives.dll\",\n"
<< "                                \"bcrypt.dll\",\n"
<< "                                \"cryptbase.dll\",\n"
<< "                                \"advapi32.dll\"}) {\n"
<< "            HMODULE module = LoadLibraryA(dll);\n"
<< "            if (!module) continue;\n"
<< "            for (const char* symbol : {\"ProcessPrng\",\n"
<< "                                       \"SystemFunction036\"}) {\n"
<< "                const auto fn = reinterpret_cast<BOOLEAN(WINAPI*)(PVOID, ULONG)>(\n"
<< "                    GetProcAddress(module, symbol));\n"
<< "                if (!fn) continue;\n"
<< "                unsigned char seed[16];\n"
<< "                fn(seed, static_cast<ULONG>(sizeof(seed)));\n"
<< "            }\n"
<< "        }\n"
<< "        // rand_s() walks the full msvcrt -> cryptbase (delay-loaded)\n"
<< "        // -> bcryptPrimitives chain; warming it completes the chain\n"
<< "        // so later deep-stack calls take fast paths.\n"
<< "        if (HMODULE msvcrt = LoadLibraryA(\"msvcrt.dll\")) {\n"
<< "            using RandSFn = int(__cdecl*)(unsigned int*);\n"
<< "            const auto rs = reinterpret_cast<RandSFn>(\n"
<< "                GetProcAddress(msvcrt, \"rand_s\"));\n"
<< "            if (rs) { unsigned int random_seed = 0;\n"
<< "                rs(&random_seed); }\n"
<< "        }\n"
<< "        // Pre-resolve every import while the real OS stack is active.\n"
<< "        for (std::size_t index = 0; index < recovered_import_count; ++index)\n"
<< "            resolve_recovered_import(index);\n"
<< "    }\n"
<< "#endif\n"
               << "    if (!recovered_runtime_initialize(argc > 0 ? argv[0] : nullptr)) {\n"
               << "        std::cerr << \"failed to initialize recovered image\\n\"; return 2;\n"
               << "    }\n"
               << "    std::cout << \"Centrifuge recovered project: "
               << report.emittedFunctions << " functions, "
               << report.knowledgeNodes << " knowledge nodes, \"\n"
               << "              << recovered_import_count << \" imports, \"\n"
               << "              << recovered_resource_count << \" resources, entry=0x\"\n"
               << "              << std::hex << recovered_original_entry_point() << \"\\n\";\n"
               << "    if (argc > 1 && std::strcmp(argv[1], \"--run-entry\") == 0) {\n"
               << "        const int result = static_cast<int>(recovered_invoke_entry());\n"
               << "        std::cerr << \"runtime faults=\" << recovered_runtime_fault_count()\n"
               << "                  << \", dispatch misses=\" << recovered_dispatch_miss_count()\n"
               << "                  << \"\\n\";\n"
               << "        return result;\n"
               << "    }\n"
               << "    return 0;\n}\n";
    if (!writeFile(sourceDirectory / "recovered_main.cpp", mainSource.str(), error))
        return false;

    const std::string projectName = safeIdentifier(options.projectName,
                                                   "centrifuge_recovered");
    std::ostringstream cmake;
    cmake << "cmake_minimum_required(VERSION 3.16)\n"
          << "project(" << projectName << " LANGUAGES CXX)\n"
          << "set(CMAKE_CXX_STANDARD 17)\nset(CMAKE_CXX_STANDARD_REQUIRED ON)\n"
          << "add_library(recovered_program STATIC\n";
    for (const std::string& file : sourceFiles) cmake << "  " << file << "\n";
    cmake << ")\ntarget_include_directories(recovered_program PUBLIC include)\n"
          << "add_executable(recovered_verifier src/recovered_main.cpp)\n"
          << "target_link_libraries(recovered_verifier PRIVATE recovered_program)\n"
          << "file(COPY data resources dependencies DESTINATION ${CMAKE_CURRENT_BINARY_DIR})\n"
          << "configure_file(globals.json globals.json COPYONLY)\n"
          << "configure_file(image.json image.json COPYONLY)\n"
          << "configure_file(imports.json imports.json COPYONLY)\n"
          << "configure_file(entrypoint.json entrypoint.json COPYONLY)\n";
    if (!writeFile(root / "CMakeLists.txt", cmake.str(), error)) return false;

    std::ostringstream json;
    json << "{\n  \"schema\": 2,\n  \"input\": \"" << jsonString(program.path)
         << "\",\n  \"discovered_functions\": " << report.discoveredFunctions
         << ",\n  \"emitted_functions\": " << report.emittedFunctions
         << ",\n  \"decompiled_functions\": " << report.decompiledFunctions
         << ",\n  \"stubbed_functions\": " << report.stubbedFunctions
         << ",\n  \"complexity_limited_functions\": "
         << report.complexityLimitedFunctions
         << ",\n  \"unresolved_markers\": " << report.unresolvedMarkers
         << ",\n  \"imported_libraries\": " << report.importedLibraries
         << ",\n  \"imported_symbols\": " << report.importedSymbols
         << ",\n  \"data_regions\": " << report.dataRegions
         << ",\n  \"image_regions\": " << report.imageRegions
         << ",\n  \"image_bytes\": " << report.imageBytes
         << ",\n  \"resources\": " << report.resources
         << ",\n  \"entry_point\": " << report.entryPoint
         << ",\n  \"entry_point_recovered\": "
         << (report.entryPointRecovered ? "true" : "false")
         << ",\n  \"knowledge_nodes\": " << report.knowledgeNodes
         << ",\n  \"knowledge_edges\": " << report.knowledgeEdges << "\n}\n";
    if (!writeFile(root / "recovery_report.json", json.str(), error))
        return false;
    report.generated = true;
    return true;
}

} // namespace centrifuge
