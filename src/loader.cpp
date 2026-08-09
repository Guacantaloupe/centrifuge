// centrifuge - a Ghidra reimplementation in C++17
// loader.cpp - format dispatch
#include "centrifuge/loader.hpp"

#include <fstream>
#include <iterator>

namespace centrifuge {
namespace {

std::optional<std::vector<uint8_t>> readFileBytes(const std::string& path,
                                                  std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        err = "cannot open file: " + path;
        return std::nullopt;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    if (data.empty()) {
        err = "empty file";
        return std::nullopt;
    }
    return data;
}

} // namespace

// format front ends (defined in loader_elf.cpp / loader_pe.cpp)
std::optional<Program> loadElf(const std::vector<uint8_t>& data,
                               const std::string& path, std::string& err);
std::optional<Program> loadPe(const std::vector<uint8_t>& data,
                              const std::string& path, std::string& err);

std::optional<Program> loadFile(const std::string& path, std::string& err) {
    auto data = readFileBytes(path, err);
    if (!data) return std::nullopt;

    if (data->size() >= 4 && (*data)[0] == 0x7F && (*data)[1] == 'E' &&
        (*data)[2] == 'L' && (*data)[3] == 'F')
        return loadElf(*data, path, err);
    if (data->size() >= 2 && (*data)[0] == 'M' && (*data)[1] == 'Z')
        return loadPe(*data, path, err);

    err = "unsupported format (only ELF and PE/MZ supported so far)";
    return std::nullopt;
}

} // namespace centrifuge
