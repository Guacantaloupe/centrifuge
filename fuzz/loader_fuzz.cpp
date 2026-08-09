#include <cstddef>
#include <cstdint>
#include <string>

#include "centrifuge/loader.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string error;
    centrifuge::LoadOptions options;
    options.maxMappedBytes = 16ULL << 20;
    (void)centrifuge::loadData(data, size, "<fuzz-input>", options, error);
    return 0;
}
