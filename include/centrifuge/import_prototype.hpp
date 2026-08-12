// centrifuge - import prototype recovery (Phase 6 of the Native Source
// Recovery Backend).  DLL imports have no machine code to analyze, so their
// prototypes are recovered from the union of every call site: argument
// widths/types, the number of ABI registers actually used, stack arguments,
// and how the return value is consumed.  A small CRT/Win32 knowledge table
// seeds well-known symbols; call-site evidence always wins on width.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "centrifuge/ir.hpp"
#include "centrifuge/loader.hpp"

namespace centrifuge {

struct ImportPrototype {
    std::string name;    // exported symbol name ("" when by-ordinal)
    std::string library; // DLL file name
    uint64_t iatAddress = 0;
    bool byOrdinal = false;
    FunctionSignature signature; // recovered prototype
    size_t callCount = 0;
    // Evidence aggregates.
    size_t maxRegisterArguments = 0; // most registers used at any call site
    bool anyStackArguments = false;  // any call site pushes stack args
    bool anyReturnValue = false;
    bool returnDereferenced = false;
    bool returnArithmetic = false;
    bool returnBoolean = false;
    int returnWidthBytes = 0;
    std::vector<DataType> mergedArgumentTypes; // per ABI register slot
    std::vector<int> mergedArgumentWidths;     // per ABI register slot
    std::vector<bool> argumentAddressUsed;     // per ABI register slot
};

class ImportPrototypeRecovery {
public:
    // Aggregate every direct call site in the program analysis.
    void aggregate(const ProgramAnalysis& analysis, const Program& program);

    // Seed well-known CRT/Win32 signatures by symbol name (evidence below
    // only refines widths, never invents parameters).
    void applyKnownPrototypes();

    std::optional<ImportPrototype> prototypeFor(uint64_t iatAddress) const;
    const std::map<uint64_t, ImportPrototype>& prototypes() const {
        return prototypes_;
    }

private:
    std::map<uint64_t, ImportPrototype> prototypes_;
};

} // namespace centrifuge
