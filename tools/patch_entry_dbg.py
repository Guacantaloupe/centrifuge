p = 'build-obs/src/recovered_metadata.cpp'
t = open(p, encoding='utf-8', errors='replace').read()
old = '''std::uint64_t recovered_invoke_entry() {
    if (!recovered_runtime_initialize(nullptr)) return 0;
    recovered_run_tls_callbacks();
    return static_cast<std::uint64_t>(entry(0, 0, 0, 0));
}'''
new = '''std::uint64_t recovered_invoke_entry() {
    std::fprintf(stderr, "[entry] init\\n");
    if (!recovered_runtime_initialize(nullptr)) return 0;
    std::fprintf(stderr, "[entry] tls\\n");
    recovered_run_tls_callbacks();
    std::fprintf(stderr, "[entry] call\\n");
    std::fflush(stderr);
    const std::uint64_t result = static_cast<std::uint64_t>(entry(0, 0, 0, 0));
    std::fprintf(stderr, "[entry] done\\n");
    return result;
}'''
if old in t:
    t = t.replace(old, new)
    open(p, 'w', encoding='utf-8', newline='\n').write(t)
    print('entry stages added')
else:
    print('pattern not found')
