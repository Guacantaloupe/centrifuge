// Temporary validation: emit a full decompileTyped native-view function
// for a real Blender trampoline and verify it compiles with g++.
// Usage: validate_compile <x86-64.slaspec> <image.bin> <addr> <name>
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
    if (argc < 5) {
        std::fprintf(stderr,
                     "usage: %s <x86-64.slaspec> <image.bin> <addr> <name>\n",
                     argv[0]);
        return 1;
    }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 1;
    std::ostringstream ss;
    ss << f.rdbuf();
    SleighEngine eng;
    std::string err;
    if (!eng.loadSpec(ss.str(), err)) return 2;

    std::ifstream image(argv[2], std::ios::binary | std::ios::ate);
    if (!image) return 2;
    const std::streamsize imageSize = image.tellg();
    std::vector<uint8_t> bytes(static_cast<size_t>(imageSize));
    image.seekg(0);
    image.read(reinterpret_cast<char*>(bytes.data()), imageSize);

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

    const uint64_t addr = std::strtoull(argv[3], nullptr, 0);
    const std::string architecture = "x86-64-win64";
    FunctionSignature signature;
    signature.returnType = DataType{TypeKind::UNSIGNED_INT, 64, 1};
    const uint64_t win64ArgRegisters[] = {8, 16, 64, 72}; // rcx rdx r8 r9
    for (int i = 0; i < 4; ++i) {
        FunctionParameter parameter;
        parameter.name = "param" + std::to_string(i + 1);
        parameter.type = DataType{TypeKind::UNSIGNED_INT, 64, 1};
        parameter.registerOffset = win64ArgRegisters[i];
        signature.parameters.push_back(parameter);
    }
    const std::string function = decompileTyped(
        eng, read, addr, addr + 0x2000, architecture, argv[4], signature,
        [](uint64_t) { return std::string(); }, nullptr,
        /*useRecoveredRuntime=*/false);
    std::printf("%s\n", function.c_str());
    std::ofstream out("tools/_trampoline_check.cpp");
    out << "#include <cstdint>\n#include <cstddef>\n" << function << "\n";
    out.close();
    return 0;
}
