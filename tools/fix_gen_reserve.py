import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'src\project_recovery.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''Reserve the sparse span and commit only actual regions.\n"
        << "    if (original_image_begin >= 0x10000U &&\n"
        << "        original_image_end > original_image_begin) {\n"
        << "        SYSTEM_INFO systemInfo{}; GetSystemInfo(&systemInfo);\n"
        << "        const std::uintptr_t granularity = systemInfo.dwAllocationGranularity;\n"
        << "        const std::uintptr_t pageSize = systemInfo.dwPageSize;\n"
        << "        const std::uintptr_t reserveBegin =\n"
        << "            original_image_begin & ~(granularity - 1U);\n"
        << "        const std::uintptr_t reserveEnd =\n"
        << "            (original_image_end + granularity - 1U) & ~(granularity - 1U);'''
new = '''Reserve the sparse span and commit only actual regions.\n"
        << "    // Reserve the whole sparse span, extended past original_image_end\n"
        << "    // when the last region (e.g. .reloc) runs beyond the PE SizeOfImage\n"
        << "    // that original_image_end was derived from.  Every region must be\n"
        << "    // readable at its fixed address for native execution.\n"
        << "    if (original_image_begin >= 0x10000U) {\n"
        << "        SYSTEM_INFO systemInfo{}; GetSystemInfo(&systemInfo);\n"
        << "        const std::uintptr_t granularity = systemInfo.dwAllocationGranularity;\n"
        << "        const std::uintptr_t pageSize = systemInfo.dwPageSize;\n"
        << "        std::uintptr_t imageEnd = original_image_end;\n"
        << "        for (const auto& region : loaded)\n"
        << "            if (region.address + region.bytes.size() > imageEnd)\n"
        << "                imageEnd = region.address + region.bytes.size();\n"
        << "        const std::uintptr_t reserveBegin =\n"
        << "            original_image_begin & ~(granularity - 1U);\n"
        << "        const std::uintptr_t reserveEnd =\n"
        << "            (imageEnd + granularity - 1U) & ~(granularity - 1U);'''
assert old in src, 'anchor missing'
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('reserve extension fixed in generator')
