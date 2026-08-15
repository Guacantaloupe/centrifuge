import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'src/recovered_runtime.cpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()

# 1. 加全局 histogram（在 runtime_faults 声明后）
anchor = 'std::atomic<std::uint64_t> runtime_dispatch_misses{0};'
assert anchor in s, 'anchor missing'
hist = (anchor + '\n'
        '// fault address histogram (diagnostics; top offenders printed at exit)\n'
        'static std::mutex g_fault_hist_mutex;\n'
        'static std::unordered_map<std::uintptr_t, std::uint64_t> g_fault_hist;\n'
        'static void recovered_note_fault(std::uintptr_t a) {\n'
        '    std::lock_guard<std::mutex> g(g_fault_hist_mutex);\n'
        '    ++g_fault_hist[a];\n'
        '}\n')
s = s.replace(anchor, hist, 1)

# 2. translate 函数体内所有 ++runtime_faults 前插 recovered_note_fault(address)
m = re.search(r'void\*\s+recovered_translate_address\(', s)
start = m.start()
nxt = s.find('\n}', start)
body = s[start:nxt]
cnt = body.count('++runtime_faults')
body = body.replace('++runtime_faults', 'recovered_note_fault(address); ++runtime_faults')
s = s[:start] + body + s[nxt:]
print('translate fault sites instrumented:', cnt)

# 3. recovered_report_process_exit 打印 top faults（在 first missing 打印前）
anchor2 = '    std::fflush('
i = s.find(anchor2)
assert i > 0, 'fflush anchor missing'
top_print = ('    if (!g_fault_hist.empty()) {\n'
             '        std::vector<std::pair<std::uintptr_t, std::uint64_t>> h(g_fault_hist.begin(), g_fault_hist.end());\n'
             '        std::sort(h.begin(), h.end(), [](const auto& a, const auto& b) { return a.second > b.second; });\n'
             '        std::fprintf(stderr, "top fault addresses:");\n'
             '        for (size_t k = 0; k < h.size() && k < 12; ++k)\n'
             '            std::fprintf(stderr, " 0x%llx(%llu)", static_cast<unsigned long long>(h[k].first),\n'
             '                        static_cast<unsigned long long>(h[k].second));\n'
             '        std::fprintf(stderr, "\\n");\n'
             '    }\n')
s = s[:i] + top_print + s[i:]
open(p, 'w', encoding='utf-8', newline='').write(s)
print('histogram + top-print added')
