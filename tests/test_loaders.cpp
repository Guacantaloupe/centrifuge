// Loader boundary and malformed-input regression tests.
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "centrifuge/loader.hpp"
#include "centrifuge/memory.hpp"
#include "centrifuge/analysis.hpp"

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

void put16(std::vector<uint8_t>& data, size_t off, uint16_t value) {
    for (unsigned i = 0; i < 2; ++i)
        data[off + i] = static_cast<uint8_t>(value >> (i * 8));
}

void put64(std::vector<uint8_t>& data, size_t off, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        data[off + i] = static_cast<uint8_t>(value >> (i * 8));
}

std::vector<uint8_t> makeTlsPe64() {
    constexpr uint64_t imageBase = 0x140000000ULL;
    std::vector<uint8_t> data(0x600, 0);
    data[0] = 'M'; data[1] = 'Z';
    put32(data, 0x3c, 0x80);
    put32(data, 0x80, 0x00004550);
    put16(data, 0x84, 0x8664);
    put16(data, 0x86, 2);
    put16(data, 0x94, 240);
    constexpr size_t optional = 0x98;
    put16(data, optional, 0x20b);
    put32(data, optional + 16, 0x1010);
    put64(data, optional + 24, imageBase);
    put32(data, optional + 56, 0x3000);
    put32(data, optional + 60, 0x200);
    put32(data, optional + 108, 16);
    put32(data, optional + 112 + 9 * 8, 0x2000);
    put32(data, optional + 112 + 9 * 8 + 4, 40);
    constexpr size_t sections = optional + 240;
    std::memcpy(data.data() + sections, ".text", 5);
    put32(data, sections + 8, 0x200);
    put32(data, sections + 12, 0x1000);
    put32(data, sections + 16, 0x200);
    put32(data, sections + 20, 0x200);
    put32(data, sections + 36, 0x60000020);
    constexpr size_t writable = sections + 40;
    std::memcpy(data.data() + writable, ".data", 5);
    put32(data, writable + 8, 0x200);
    put32(data, writable + 12, 0x2000);
    put32(data, writable + 16, 0x200);
    put32(data, writable + 20, 0x400);
    put32(data, writable + 36, 0xc0000040);
    put64(data, 0x400, imageBase + 0x2050);
    put64(data, 0x408, imageBase + 0x2070);
    put64(data, 0x410, imageBase + 0x2070);
    put64(data, 0x418, imageBase + 0x2080);
    put32(data, 0x420, 16);
    put32(data, 0x424, 0x800000);
    for (size_t index = 0; index < 0x20; ++index)
        data[0x450 + index] = static_cast<uint8_t>(0x80 + index);
    put64(data, 0x480, imageBase + 0x1010);
    put64(data, 0x488, 0);
    return data;
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
    CHECK(pe && pe->entryPoint != 0, "PE AddressOfEntryPoint is preserved");
    CHECK(pe && !pe->dataRegions.empty() &&
              pe->dataRegions.front().initializedSize <=
                  pe->dataRegions.front().size,
          "PE non-executable global-data regions are preserved");
    {
        const auto tlsPe = makeTlsPe64();
        auto tlsProgram = loadData(tlsPe, "tls-pe64-memory", error);
        CHECK(tlsProgram && tlsProgram->tls.has_value(),
              "PE64 TLS directory is preserved");
        CHECK(tlsProgram && tlsProgram->tls &&
                  tlsProgram->tls->rawDataStart == 0x140002050ULL &&
                  tlsProgram->tls->rawDataEnd == 0x140002070ULL &&
                  tlsProgram->tls->addressOfIndex == 0x140002070ULL &&
                  tlsProgram->tls->zeroFillSize == 16,
              "PE64 TLS template and index metadata are exact");
        CHECK(tlsProgram && tlsProgram->tls &&
                  tlsProgram->tls->callbacks.size() == 1 &&
                  tlsProgram->tls->callbacks.front() == 0x140001010ULL,
              "PE64 TLS callback array is recovered");

        auto malformedTls = tlsPe;
        put64(malformedTls, 0x408, 0x14000204fULL);
        CHECK(rejected(malformedTls),
              "backwards PE TLS template range rejected");
    }

    {
        // Native-subsystem (driver) PE: subsystem metadata is recovered and
        // the entry point is discovered as DriverEntry.
        auto driverPe = makeTlsPe64();
        put16(driverPe, 0x98 + 68, 1); // IMAGE_SUBSYSTEM_NATIVE
        auto driver = loadData(driverPe, "driver-pe64-memory", error);
        CHECK(driver && driver->peSubsystem == 1 && isKernelDriver(*driver),
              "PE native subsystem recognized as kernel driver");
        const auto funcs = findFunctions(*driver, nullptr);
        bool hasDriverEntry = false;
        for (const auto& f : funcs)
            if (f.name == "DriverEntry" && f.src == Function::ENTRY)
                hasDriverEntry = true;
        CHECK(hasDriverEntry, "kernel driver entry named DriverEntry");
        auto consolePe = makeTlsPe64();
        const auto consoleProg = loadData(consolePe, "console-pe64-memory", error);
        CHECK(consoleProg && consoleProg->peSubsystem == 0 &&
                  !isKernelDriver(*consoleProg),
              "unspecified PE subsystem is not a kernel driver");
    }

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
