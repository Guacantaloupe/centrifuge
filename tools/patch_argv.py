import re
p = 'build-recheck52/src/external_stubs.cpp'
t = open(p, encoding='utf-8-sig', errors='replace').read()
old = ('external_140479490(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {\n'
       '    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;\n'
       '    return 0;\n}')

def repl(m):
    return ('external_140479490(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7) {\n'
            '    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;\n'
            '    // Native: Blender-internal wide->narrow argv conversion (wmain argv\n'
            '    // path). Stub returned 0, so every converted argv entry became NULL\n'
            '    // and the init strcmp(0, "...") crashed in ucrtbase.  Implement with\n'
            '    // the host WideCharToMultiByte.\n'
            '    if (!a0) return 0;\n'
            '    const wchar_t* wstr = reinterpret_cast<const wchar_t*>(a0);\n'
            '    const int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);\n'
            '    if (len <= 0) return 0;\n'
            '    char* buf = static_cast<char*>(std::malloc(static_cast<std::size_t>(len)));\n'
            '    if (!buf) return 0;\n'
            '    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buf, len, nullptr, nullptr);\n'
            '    return reinterpret_cast<std::uint64_t>(buf);\n}')
if old in t:
    t = re.sub(re.escape(old), repl, t, count=1)
    open(p, 'w', encoding='utf-8-sig').write(t)
    print('patched external_140479490 with WideCharToMultiByte')
else:
    print('pattern not found')
    i = t.find('external_140479490')
    print(repr(t[i:i+250]))
