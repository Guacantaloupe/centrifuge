import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# commit 打印加 region 名和 address
old = '''            std::fprintf(stderr, "[MAP] commit 0x%llx+0x%llx\\n", (unsigned long long)pageBegin, (unsigned long long)(pageEnd - pageBegin));'''
new = '''            std::fprintf(stderr, "[MAP] commit %s addr=0x%llx size=%llu pageBegin=0x%llx+0x%llx\\n",
                         region.name.c_str(), (unsigned long long)region.address,
                         (unsigned long long)region.bytes.size(),
                         (unsigned long long)pageBegin,
                         (unsigned long long)(pageEnd - pageBegin));'''
assert old in src
src = src.replace(old, new)
# RuntimeRegion 加 name 字段
old2 = 'struct RuntimeRegion { std::uintptr_t address = 0; std::vector<std::uint8_t> bytes; void* mapped = nullptr; };'
new2 = 'struct RuntimeRegion { std::string name; std::uintptr_t address = 0; std::vector<std::uint8_t> bytes; void* mapped = nullptr; };'
assert old2 in src
src = src.replace(old2, new2)
# region 赋值时加 name
old3 = 'RuntimeRegion region; region.address = descriptor.address;'
new3 = 'RuntimeRegion region; region.name = descriptor.name ? descriptor.name : ""; region.address = descriptor.address;'
assert old3 in src
src = src.replace(old3, new3)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('region name diagnostics added')
