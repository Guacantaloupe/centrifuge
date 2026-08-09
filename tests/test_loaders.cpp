// Loader boundary and malformed-input regression tests.
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "centrifuge/loader.hpp"
#include "centrifuge/memory.hpp"

using namespace centrifuge;

namespace {

int failures = 0;

#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL: %s\n", msg);                            \
            ++failures;                                                 \
        }                                                               \
    } while (0)

std::vector<uint8_t> readAll(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>());
}

void put32(std::vector<uint8_t>& data, size_t off, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        data[off + i] = static_cast<uint8_t>(value >> (i * 8));
}

void put64(std::vector<uint8_t>& data, size_t off, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        data[off + i] = static_cast<uint8_t>(value >> (i * 8));
}

bool rejected(const std::vector<uint8_t>& data) {
    std::string error;
    return !loadData(data, "<malformed>", error).has_value() && !error.empty();
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: test_loaders <elf32> <elf64> <pe64>\n");
        return 2;
    }
    const auto elf32 = readAll(argv[1]);
    const auto elf64 = readAll(argv[2]);
    const auto pe64 = readAll(argv[3]);
    CHECK(!elf32.empty() && !elf64.empty() && !pe64.empty(),
          "sample inputs are readable");

    std::string error;
    auto p32 = loadData(elf32, "elf32-memory", error);
    CHECK(p32 && p32->format == "ELF32", "valid ELF32 memory load");
    auto p64 = loadData(elf64.data(), elf64.size(), "elf64-memory", error);
    CHECK(p64 && p64->format == "ELF64", "valid ELF64 pointer load");
    auto pe = loadData(pe64, "pe64-memory", error);
    CHECK(pe && pe->format == "PE32+", "valid PE32+ memory load");

    LoadOptions tinyLimit;
    tinyLimit.maxMappedBytes = 1;
    CHECK(!loadData(elf64.data(), elf64.size(), "limited", tinyLimit, error),
          "caller mapping limit enforced");
    CHECK(!loadData(nullptr, 1, "null", error),
          "null non-empty input buffer rejected");

    CHECK(rejected({}), "empty input rejected");
    CHECK(rejected({0x7f, 'E', 'L', 'F'}), "truncated ELF rejected");
    CHECK(rejected({0x4d, 0x5a}), "truncated PE rejected");

    {
        auto data = elf64;
        put64(data, 32, UINT64_MAX); // e_phoff
        CHECK(rejected(data), "overflowing ELF program-header offset rejected");
    }
    {
        auto data = elf64;
        put64(data, 64 + 8, UINT64_MAX - 4); // first PT_LOAD p_offset
        put64(data, 64 + 32, 16);            // p_filesz
        CHECK(rejected(data), "overflowing ELF segment file range rejected");
    }
    {
        auto data = elf64;
        put64(data, 64 + 40, UINT64_MAX); // first PT_LOAD p_memsz
        CHECK(rejected(data), "overflowing ELF virtual range rejected");
    }
    {
        auto data = elf64;
        put64(data, 40, UINT64_MAX); // e_shoff
        CHECK(rejected(data), "overflowing ELF section-table offset rejected");
    }
    {
        auto data = pe64;
        put32(data, 0x3c, UINT32_MAX); // e_lfanew
        CHECK(rejected(data), "out-of-file PE header offset rejected");
    }
    {
        auto data = pe64;
        data.resize(100);
        CHECK(rejected(data), "truncated PE optional header rejected");
    }
    {
        auto data = pe64;
        constexpr size_t firstSection = 0x40 + 24 + 240;
        put32(data, firstSection + 16, 32);         // SizeOfRawData
        put32(data, firstSection + 20, UINT32_MAX); // PointerToRawData
        CHECK(rejected(data), "overflowing PE raw section range rejected");
    }
    {
        auto data = pe64;
        constexpr size_t firstSection = 0x40 + 24 + 240;
        const char name[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
        for (size_t i = 0; i < sizeof(name); ++i) data[firstSection + i] = name[i];
        auto program = loadData(data, "eight-char-section", error);
        CHECK(program && !program->sections.empty() &&
                  program->sections[0].name == "12345678",
              "non-NUL-terminated PE section name is bounded");
    }
    {
        MemoryImage memory;
        CHECK(!memory.addBlock("overflow", UINT64_MAX - 1,
                               std::vector<uint8_t>(4), 0),
              "overflowing memory block rejected");
    }

    if (failures == 0) {
        std::printf("test_loaders: ALL PASSED\n");
        return 0;
    }
    std::printf("test_loaders: %d FAILURES\n", failures);
    return 1;
}
