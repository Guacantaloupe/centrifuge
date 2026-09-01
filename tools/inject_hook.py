import io, sys
p = r'build-recheck54\src\recovered_main.cpp'
src = io.open(p, encoding='utf-8').read()
if 'recovered_exception_hook' in src:
    print('hook already present')
    sys.exit(0)
hook = '''#ifdef _WIN32
static LONG WINAPI recovered_exception_hook(PEXCEPTION_POINTERS info) {
    if (!info || !info->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const auto code = info->ExceptionRecord->ExceptionCode;
    auto* ctx = info->ContextRecord;
    std::fprintf(stderr, "[EXC] 0x%08lx rip=%p rsp=%p rcx=%p rdx=%p r8=%p r9=%p rbx=%p rdi=%p rsi=%p\\n",
                 (unsigned long)code,
                 (void*)(ctx ? ctx->Rip : 0), (void*)(ctx ? ctx->Rsp : 0),
                 (void*)(ctx ? ctx->Rcx : 0), (void*)(ctx ? ctx->Rdx : 0),
                 (void*)(ctx ? ctx->R8 : 0), (void*)(ctx ? ctx->R9 : 0),
                 (void*)(ctx ? ctx->Rbx : 0), (void*)(ctx ? ctx->Rdi : 0),
                 (void*)(ctx ? ctx->Rsi : 0));
    void* frames[12]{};
    const auto count = CaptureStackBackTrace(0, 12, frames, nullptr);
    std::fprintf(stderr, "[BT]");
    for (std::size_t i = 0; i < count; ++i)
        std::fprintf(stderr, " %p", frames[i]);
    std::fprintf(stderr, "\\n");
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif
int main(int argc, char** argv) {
    std::fprintf(stderr, "");
#ifdef _WIN32
    AddVectoredExceptionHandler(1, recovered_exception_hook);
#endif
'''
old = 'int main(int argc, char** argv) {\n    std::fprintf(stderr, "");'
assert old in src, 'anchor missing'
src = src.replace(old, hook, 1)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('hook injected')
