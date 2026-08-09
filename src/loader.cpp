// centrifuge - a Ghidra reimplementation in C++17
// loader.cpp - format dispatch
#include "centrifuge/loader.hpp"

#include <fstream>
#include <iterator>
#include <limits>

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
                               const std::string& path, uint64_t maxMappedBytes,
                               std::string& err);
std::optional<Program> loadPe(const std::vector<uint8_t>& data,
                              const std::string& path, uint64_t maxMappedBytes,
                              std::string& err);

std::optional<Program> loadFile(const std::string& path, std::string& err) {
    auto data = readFileBytes(path, err);
    if (!data) return std::nullopt;

    return loadData(*data, path, err);
}

std::optional<Program> loadData(const std::vector<uint8_t>& data,
                                const std::string& virtualPath,
                                std::string& err) {
    return loadData(data, virtualPath, LoadOptions{}, err);
}

std::optional<Program> loadData(const std::vector<uint8_t>& data,
                                const std::string& virtualPath,
                                const LoadOptions& options,
                                std::string& err) {
    if (data.empty()) {
        err = "empty file";
        return std::nullopt;
    }

    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' &&
        data[2] == 'L' && data[3] == 'F')
        return loadElf(data, virtualPath, options.maxMappedBytes, err);
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z')
        return loadPe(data, virtualPath, options.maxMappedBytes, err);

    err = "unsupported format (only ELF and PE/MZ supported so far)";
    return std::nullopt;
}

std::optional<Program> loadData(const uint8_t* data, size_t size,
                                const std::string& virtualPath,
                                std::string& err) {
    return loadData(data, size, virtualPath, LoadOptions{}, err);
}

std::optional<Program> loadData(const uint8_t* data, size_t size,
                                const std::string& virtualPath,
                                const LoadOptions& options,
                                std::string& err) {
    if (size != 0 && data == nullptr) {
        err = "null input buffer";
        return std::nullopt;
    }
    if (size == 0)
        return loadData(std::vector<uint8_t>{}, virtualPath, options, err);
    return loadData(std::vector<uint8_t>(data, data + size), virtualPath,
                    options, err);
}

} // namespace centrifuge
