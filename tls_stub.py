import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'src/external_stubs.cpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()
old = ('std::uint64_t external_1446a4cf0(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {\n'
       '    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;\n'
       '    return 0;\n'
       '}')
new = ('std::uint64_t external_1446a4cf0(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {\n'
       '    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;\n'
       '    // Native: TLS-block accessor; first qword of the returned 16-byte header\n'
       '    // points at the per-thread data block.  Plain stub returned 0, so\n'
       '    // FUN_46A1DB0 translate(0) faulted 12k+ times.  Return a persistent\n'
       '    // zero-initialized block (single-threaded recovered runtime).\n'
       '    static std::uint64_t tls_block[512] = {};\n'
       '    static std::uint64_t header[2] = { reinterpret_cast<std::uint64_t>(tls_block), 0 };\n'
       '    return reinterpret_cast<std::uint64_t>(header);\n'
       '}')
assert old in s, 'stub anchor missing'
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('external_1446a4cf0 TLS-block stub applied')
