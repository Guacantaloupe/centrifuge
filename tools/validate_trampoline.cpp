// Temporary validation harness: decompile known Blender 5.2 data-slot
// trampolines from the flat image (build-blender52/project/data/image.bin)
// with the NEW decompiler, in both recovered-runtime and native view.
// Usage: validate_trampoline <x86-64.slaspec> <image.bin> <addr>...
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "centrifuge/decompile.hpp"
#include "centrifuge/sleigh.hpp"

using namespace centrifuge;

struct Region {
    uint64_t va;
    uint64_t fileOffset;
    uint64_t size;
};

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr,
                     "usage: %s <x86-64.slaspec> <image.bin> <addr>...\n",
                     argv[0]);
        return 1;
    }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 1;
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) {
        std::fprintf(stderr, "spec load failed: %s\n", err.c_str());
        return 2;
    }

    std::ifstream image(argv[2], std::ios::binary | std::ios::ate);
    if (!image) {
        std::fprintf(stderr, "cannot open image: %s\n", argv[2]);
        return 2;
    }
    const std::streamsize imageSize = image.tellg();
    std::vector<uint8_t> bytes(static_cast<size_t>(imageSize));
    image.seekg(0);
    image.read(reinterpret_cast<char*>(bytes.data()), imageSize);

    // Blender 5.2 flat image layout (from recovered_metadata.cpp).
    const Region regions[] = {
        {0x140000000ULL, 0ULL, 1024ULL},
        {0x140001000ULL, 1024ULL, 79754240ULL},
        {0x144A00000ULL, 79755264ULL, 26072576ULL},
        {0x146600000ULL, 105827840ULL, 16405568ULL},
        {0x147600000ULL, 122233408ULL, 2483712ULL},
        {0x147770000ULL, 124717120ULL, 2560ULL},
        {0x147771000ULL, 124719680ULL, 1024ULL},
        {0x147772000ULL, 124720704ULL, 307712ULL},
        {0x1477BE000ULL, 125028416ULL, 284672ULL},
    };
    auto read = [&](uint64_t a, void* buf, size_t n) -> bool {
        for (const Region& r : regions) {
            if (a < r.va || a >= r.va + r.size) continue;
            const uint64_t off = r.fileOffset + (a - r.va);
            if (off + n > bytes.size()) return false;
            std::memcpy(buf, bytes.data() + off, n);
            return true;
        }
        return false;
    };

    const std::string architecture = "x86-64-win64";
    for (int i = 3; i < argc; ++i) {
        uint64_t addr = std::strtoull(argv[i], nullptr, 0);
        std::printf("========== FUN %s ==========\n", argv[i]);
        {
            uint8_t first = 0;
            const bool readable = read(addr, &first, 1);
            std::printf("raw read: %s (byte=%02x)\n",
                        readable ? "ok" : "FAILED", first);
        }
        {
            PcodeInsn probe;
            std::string disErr;
            if (!eng.disassemble(read, addr, probe, disErr)) {
                std::printf("disassemble @%s failed: %s\n", argv[i],
                            disErr.c_str());
            } else {
                std::printf("first insn: %s (%zu bytes)\n",
                            probe.text.c_str(), probe.ops.size());
            }
        }
        const std::string recovered = decompile(
            eng, read, addr, addr + 0x2000,
            [](uint64_t) { return std::string(); }, nullptr, architecture,
            /*useRecoveredRuntime=*/true);
        std::printf("--- recovered runtime ---\n%s\n", recovered.c_str());
        const std::string native = decompile(
            eng, read, addr, addr + 0x2000,
            [](uint64_t) { return std::string(); }, nullptr, architecture,
            /*useRecoveredRuntime=*/false);
        std::printf("--- native view ---\n%s\n", native.c_str());
    }
    return 0;
}
