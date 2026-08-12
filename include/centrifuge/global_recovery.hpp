// centrifuge - global object recovery (Phase 8 of the Native Source
// Recovery Backend).  Constant-address LOAD/STORE accesses in the data
// segment cluster into named global objects with field-level access
// evidence, so native output can emit `g_data_1405f000.field` instead of
// raw absolute-address casts.  The recovered project (Machine Semantic
// oracle) keeps its absolute-address expressions untouched.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "centrifuge/cfg.hpp"
#include "centrifuge/loader.hpp"

namespace centrifuge {

struct GlobalField {
    uint64_t byteOffset = 0;
    int widthBytes = 0;
    bool written = false;
};

struct GlobalObject {
    uint64_t address = 0;
    uint64_t size = 0;
    std::string name;
    std::vector<GlobalField> fields;
};

class GlobalObjectRecovery {
public:
    // Scan the CFG for constant-address data accesses.  `symbolName` maps an
    // address to an existing symbol name (exports/data symbols), or "".
    void analyze(const CfgBuilder& cfg, const MemoryImage& memory,
                 const std::function<std::string(uint64_t)>& symbolName =
                     {});
    const std::vector<GlobalObject>& objects() const { return objects_; }
    // Exact object containing the access at `address` (or null).
    const GlobalObject* objectAt(uint64_t address) const;

private:
    std::vector<GlobalObject> objects_;
    std::map<uint64_t, size_t> byAddress_;
};

} // namespace centrifuge
