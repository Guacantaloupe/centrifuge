import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''    if (original_image_begin >= 0x10000U &&
        original_image_end > original_image_begin) {
        SYSTEM_INFO systemInfo{}; GetSystemInfo(&systemInfo);
        const std::uintptr_t granularity = systemInfo.dwAllocationGranularity;
        const std::uintptr_t pageSize = systemInfo.dwPageSize;
        const std::uintptr_t reserveBegin =
            original_image_begin & ~(granularity - 1U);
        const std::uintptr_t reserveEnd =
            (original_image_end + granularity - 1U) & ~(granularity - 1U);'''
new = '''    // Reserve the whole sparse span, extended past original_image_end
    // when the last region (e.g. .reloc) runs beyond the PE SizeOfImage
    // that original_image_end was derived from.  Every region must be
    // readable at its fixed address for the relocation walk and native
    // execution.
    if (original_image_begin >= 0x10000U) {
        SYSTEM_INFO systemInfo{}; GetSystemInfo(&systemInfo);
        const std::uintptr_t granularity = systemInfo.dwAllocationGranularity;
        const std::uintptr_t pageSize = systemInfo.dwPageSize;
        std::uintptr_t imageEnd = original_image_end;
        for (const auto& region : loaded)
            if (region.address + region.bytes.size() > imageEnd)
                imageEnd = region.address + region.bytes.size();
        const std::uintptr_t reserveBegin =
            original_image_begin & ~(granularity - 1U);
        const std::uintptr_t reserveEnd =
            (imageEnd + granularity - 1U) & ~(granularity - 1U);'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('reserve range extended to cover all regions')
