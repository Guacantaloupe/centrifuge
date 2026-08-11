// centrifuge - executable-image semantic coverage audit
#pragma once

#include <cstddef>
#include <map>
#include <string>

#include "centrifuge/loader.hpp"
#include "centrifuge/sleigh.hpp"

namespace centrifuge {

struct SemanticCoverageReport {
    size_t executableBytes = 0;
    size_t decodedBytes = 0;
    size_t instructions = 0;
    size_t decodeFailures = 0;
    size_t emptySemantics = 0;
    size_t unimplementedOperations = 0;
    std::map<std::string, size_t> missingByMnemonic;
    double byteCoverage() const {
        return executableBytes
                   ? static_cast<double>(decodedBytes) /
                         static_cast<double>(executableBytes)
                   : 0.0;
    }
};

// Static constructor evidence.  An inline semantic body is a specification
// proof; an empty constructor is deliberately reported as unproven until a
// shared semantic provider plus an executable reference vector is attached.
struct ConstructorProofReport {
    size_t constructors = 0;
    size_t inlineSpecifications = 0;
    size_t sharedSpecifications = 0;
    size_t unproven = 0;
    std::map<std::string, size_t> unprovenByMnemonic;
};

SemanticCoverageReport auditSemanticCoverage(const Program& program,
                                             const SleighEngine& engine,
                                             size_t maxInstructions = 1000000);
ConstructorProofReport auditConstructorProof(const SleighEngine& engine);

} // namespace centrifuge
