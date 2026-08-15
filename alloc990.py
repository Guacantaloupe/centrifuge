import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'src/external_stubs.cpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()

# include <cstdlib> for calloc
old = '#include <cstdint>'
new = '#include <cstdint>\n#include <cstdlib>'
assert old in s
s = s.replace(old, new, 1)

# external_146588990: allocator slot (0x146588990 -> 0x140B0D580); dispatch returning 0
# starves FUN_4041ED10's 88-byte object allocation 12k times -> store-to-null faults.
# Fall back to a zeroed host block when the recovered allocator reports failure.
old = '''std::uint64_t external_146588990(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {
    const auto target = recovered_load<std::uint64_t>(0x146588990);
    if (target >= 5368709120ULL && target < 5494044672ULL)
        return recovered_dispatch(target, a0, a1, a2, a3, a4, a5, a6, a7);
    auto function = reinterpret_cast<RecoveredExternal>(target);
    return function ? function(recovered_external_argument(a0), recovered_external_argument(a1), recovered_external_argument(a2), recovered_external_argument(a3), recovered_external_argument(a4), recovered_external_argument(a5), recovered_external_argument(a6), recovered_external_argument(a7)) : 0;'''
new = '''std::uint64_t external_146588990(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {
    const auto target = recovered_load<std::uint64_t>(0x146588990);
    std::uint64_t r = 0;
    if (target >= 5368709120ULL && target < 5494044672ULL)
        r = recovered_dispatch(target, a0, a1, a2, a3, a4, a5, a6, a7);
    else {
        auto function = reinterpret_cast<RecoveredExternal>(target);
        r = function ? function(recovered_external_argument(a0), recovered_external_argument(a1), recovered_external_argument(a2), recovered_external_argument(a3), recovered_external_argument(a4), recovered_external_argument(a5), recovered_external_argument(a6), recovered_external_argument(a7)) : 0;
    }
    if (!r || r < 0x10000) {
        // allocator slot: zeroed host block keeps the object alive
        std::size_t n = static_cast<std::size_t>(a0) * static_cast<std::size_t>(a1);
        if (!n) n = 1;
        void* p = std::calloc(1, n);
        return reinterpret_cast<std::uint64_t>(p);
    }
    return r;'''
assert old in s, 'external_146588990 anchor missing'
s = s.replace(old, new, 1)

open(p, 'w', encoding='utf-8', newline='').write(s)
print('external_146588990 allocator fallback applied')
