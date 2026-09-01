# -*- coding: utf-8 -*-
# 一次性诊断：fault 地址采样（前 16 个）+ 调用方返回地址
p = 'build-recheck52/src/recovered_runtime.cpp'
t = open(p, encoding='utf-8-sig', errors='replace').read()

fn = 'void* recovered_translate_address(std::uintptr_t address, std::size_t size) {'
i = t.find(fn)
assert i != -1

# 1) 函数开头加采样状态
probe = '''void* recovered_translate_address(std::uintptr_t address, std::size_t size) {
    static std::uint64_t fault_samples[24];
    static std::uintptr_t fault_ra[24];
    static std::atomic<int> fault_count{0};
    auto sample_fault = [&]() {
        const int slot = fault_count.fetch_add(1);
        if (slot < 24) {
            fault_samples[slot] = static_cast<std::uint64_t>(address);
            fault_ra[slot] = reinterpret_cast<std::uintptr_t>(
                __builtin_return_address(0));
        }
        if (slot == 24) {
            std::fprintf(stderr, "[fault-samples]\\n");
            for (int k = 0; k < 24; ++k)
                std::fprintf(stderr, "  fault[%d] addr=0x%llx ra=0x%llx\\n", k,
                    static_cast<unsigned long long>(fault_samples[k]),
                    static_cast<unsigned long long>(fault_ra[k]));
            std::fflush(stderr);
        }
    };
'''
assert fn in t
t = t.replace(fn, probe, 1)

# 2) 3 处 faults++ 前插入采样（零页/镜像未覆盖）
old = 'const std::uint64_t faults = ++runtime_faults;'
new = 'sample_fault(); const std::uint64_t faults = ++runtime_faults;'
n = t.count(old)
print('fault++ sites:', n)
t = t.replace(old, new)

# 3) 其他 ++runtime_faults 也采样（非零页路径——镜像未覆盖/堆越界）
import re
other = [m.start() for m in re.finditer(r'\+\+runtime_faults;', t)]
print('total ++runtime_faults after:', len(other))

open(p, 'w', encoding='utf-8-sig', newline='\n').write(t)
print('patched')
