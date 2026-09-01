import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_metadata.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''std::uint64_t recovered_invoke_entry() {
    if (!recovered_runtime_initialize(nullptr)) return 0;
    recovered_run_tls_callbacks();
    return static_cast<std::uint64_t>(entry(0, 0, 0, 0));
}'''
new = '''std::uint64_t recovered_invoke_entry() {
    if (!recovered_runtime_initialize(nullptr)) return 0;
    std::fprintf(stderr, "[PE] e_lfanew=%u entryRva=%u optMagic=%u\\n",
                 *reinterpret_cast<unsigned*>(0x140000000ULL + 0x3C),
                 *reinterpret_cast<unsigned*>(0x140000000ULL + 0x3C + 24 + 16),
                 *reinterpret_cast<unsigned short*>(0x140000000ULL + 0x3C + 24));
    recovered_run_tls_callbacks();
    return static_cast<std::uint64_t>(entry(0, 0, 0, 0));
}'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('PE dump added')
