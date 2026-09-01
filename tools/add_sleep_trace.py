import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''    for (const auto& slot : runtime_iat_slots) {
        void* resolved = resolve_recovered_import(slot.second);
        if (resolved)
            *reinterpret_cast<std::uintptr_t*>(slot.first) =
                reinterpret_cast<std::uintptr_t>(resolved);
    }'''
new = '''    for (const auto& slot : runtime_iat_slots) {
        void* resolved = resolve_recovered_import(slot.second);
        if (resolved)
            *reinterpret_cast<std::uintptr_t*>(slot.first) =
                reinterpret_cast<std::uintptr_t>(resolved);
        if (slot.first == 0x145d4a230ULL)
            std::fprintf(stderr, "[IAT-SLEEP] idx=%zu resolved=%p\\n",
                         slot.second, resolved);
    }'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('sleep IAT trace added')
