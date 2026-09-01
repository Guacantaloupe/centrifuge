import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
gen = io.open(r'src\project_recovery.cpp', encoding='utf-8', errors='replace').read()
i = gen.find('#endif\n"\n               << "    std::fprintf(stderr, "");')
# 找 hook #endif 后面
j = gen.find('return EXCEPTION_CONTINUE_SEARCH;\\n"\n               << "}\\n"\n               << "#endif\\n"')
print('hook end at', j)
if j >= 0:
    print(repr(gen[j:j+400]))
