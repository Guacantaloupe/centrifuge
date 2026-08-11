// centrifuge - recompilable C++ source-project recovery
#pragma once

#include <cstddef>
#include <string>

#include "centrifuge/loader.hpp"

namespace centrifuge {

class ProgramAnalysis;
class SleighEngine;

struct ProjectRecoveryOptions {
    std::string outputDirectory;
    std::string projectName = "centrifuge_recovered";
    std::string callingConvention;
    size_t maximumFunctions = 0;
    size_t functionsPerSource = 128;
    bool emitIncompleteStubs = true;
};

struct ProjectRecoveryReport {
    size_t discoveredFunctions = 0;
    size_t emittedFunctions = 0;
    size_t decompiledFunctions = 0;
    size_t stubbedFunctions = 0;
    size_t complexityLimitedFunctions = 0;
    size_t sourceFiles = 0;
    size_t unresolvedMarkers = 0;
    size_t importedLibraries = 0;
    size_t importedSymbols = 0;
    size_t dataRegions = 0;
    size_t imageRegions = 0;
    uint64_t imageBytes = 0;
    size_t resources = 0;
    uint64_t entryPoint = 0;
    bool entryPointRecovered = false;
    size_t knowledgeNodes = 0;
    size_t knowledgeEdges = 0;
    bool generated = false;
};

bool recoverSourceProject(const Program& program, const SleighEngine& engine,
                          const ProgramAnalysis& analysis,
                          const ProjectRecoveryOptions& options,
                          ProjectRecoveryReport& report, std::string& error);

} // namespace centrifuge
