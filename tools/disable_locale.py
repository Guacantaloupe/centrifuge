import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 临时禁用 locale 预构造 (注释掉 ctor 调用)
old = '''        if (recovered_image_executable(kLocaleCtor)) {
            using LocaleCtor = std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
            const auto locale_ctor = reinterpret_cast<LocaleCtor>(kLocaleCtor);
            if (locale_ctor) locale_ctor(0, 0, 0, 0, 0, 0, 0, 0);
            *reinterpret_cast<std::uint32_t*>(kLocaleGuard) = 0xFFFFFFFFu;
        }'''
new = '''        if (recovered_image_executable(kLocaleCtor)) {
            using LocaleCtor = std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
            // TEMP: disabled to isolate the 0x140000000 table corruption
            // const auto locale_ctor = reinterpret_cast<LocaleCtor>(kLocaleCtor);
            // if (locale_ctor) locale_ctor(0, 0, 0, 0, 0, 0, 0, 0);
            *reinterpret_cast<std::uint32_t*>(kLocaleGuard) = 0xFFFFFFFFu;
        }'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('locale ctor disabled')
