# 一次性验证：external_1400b1bb0（std::string 比较器，未恢复→空 stub）
# 返回 a0 指向的值 = 与 39 行 load(rsi) 恒等 → FUN_23264F0 走插入路径（526）
# 避免 rdi=0 → map 红黑树遍历死循环（50M faults）
p = 'build-recheck52/src/external_stubs.cpp'
t = open(p, encoding='utf-8-sig', errors='replace').read()
old = '''std::uint64_t external_1400b1bb0(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;
}'''
new = '''std::uint64_t external_1400b1bb0(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return recovered_load<std::uint64_t>(a0);
}'''
assert old in t, 'stub pattern not found'
t = t.replace(old, new)
open(p, 'w', encoding='utf-8-sig', newline='\n').write(t)
print('external_1400b1bb0 patched')
