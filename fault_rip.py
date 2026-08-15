import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'src/recovered_runtime.cpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()

old = ('static std::unordered_map<std::uintptr_t, std::uint64_t> g_fault_hist;\n'
       'static void recovered_note_fault(std::uintptr_t a) {\n'
       '    std::lock_guard<std::mutex> g(g_fault_hist_mutex);\n'
       '    ++g_fault_hist[a];\n'
       '}')
new = ('struct FaultInfo { std::uint64_t count = 0; std::uintptr_t rip = 0; };\n'
       'static std::unordered_map<std::uintptr_t, FaultInfo> g_fault_hist;\n'
       'static void recovered_note_fault(std::uintptr_t a) {\n'
       '    std::lock_guard<std::mutex> g(g_fault_hist_mutex);\n'
       '    auto& f = g_fault_hist[a];\n'
       '    ++f.count;\n'
       '    if (!f.rip) f.rip = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));\n'
       '}')
assert old in s, 'hist struct anchor missing'
s = s.replace(old, new, 1)

old2 = ('        std::vector<std::pair<std::uintptr_t, std::uint64_t>> h(g_fault_hist.begin(), g_fault_hist.end());\n'
        '        std::sort(h.begin(), h.end(), [](const auto& a, const auto& b) { return a.second > b.second; });\n'
        '        std::fprintf(stderr, "top fault addresses:");\n'
        '        for (size_t k = 0; k < h.size() && k < 12; ++k)\n'
        '            std::fprintf(stderr, " 0x%llx(%llu)", static_cast<unsigned long long>(h[k].first),\n'
        '                        static_cast<unsigned long long>(h[k].second));\n'
        '        std::fprintf(stderr, "\\n");\n')
new2 = ('        std::vector<std::pair<std::uintptr_t, FaultInfo>> h(g_fault_hist.begin(), g_fault_hist.end());\n'
        '        std::sort(h.begin(), h.end(), [](const auto& a, const auto& b) { return a.second.count > b.second.count; });\n'
        '        std::fprintf(stderr, "top fault addresses (addr:count@caller_rip_exe_off):");\n'
        '        for (size_t k = 0; k < h.size() && k < 12; ++k)\n'
        '            std::fprintf(stderr, " 0x%llx:%llu@0x%llx", static_cast<unsigned long long>(h[k].first),\n'
        '                        static_cast<unsigned long long>(h[k].second.count),\n'
        '                        static_cast<unsigned long long>(h[k].second.rip - reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr))));\n'
        '        std::fprintf(stderr, "\\n");\n')
assert old2 in s, 'print anchor missing'
s = s.replace(old2, new2, 1)

open(p, 'w', encoding='utf-8', newline='').write(s)
print('RIP capture added')
