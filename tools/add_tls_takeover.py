import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 在 IAT 写回循环后加 TLS 数组接管 (在 guard 安装前)
old = '''    // MSVC /guard:cf indirect-call slot (__guard_dispatch_icall_fptr,
    // 0x145d40858) holds a file image value that is an unrelocated RVA
    // into .rdata; native callers do `call [slot]` with the real target
    // in rax and expect the slot to be a jmp-rax trampoline.  Install a
    // translating trampoline: if rax is a small RVA that maps into the
    // fixed image, add the image base first, then jump.'''
new = '''    // The image's TLS directory references 0x146deebd4 as the slot
    // where the loader normally stores the TLS index.  Because the
    // recovered image is a raw section dump, the loader never wrote
    // that index, so original machine code reads gs:[0x58 + 0*8] =
    // the MSYS2 TLS block and corrupts the host runtime's thread_local
    // state.  Claim a high TLS index for the image and point the host
    // TLS array at the simulated image TLS block instead.
    {
        auto* teb = NtCurrentTeb();
        auto** tlsArray = *reinterpret_cast<PVOID***>(
            reinterpret_cast<unsigned char*>(teb) + 0x58);
        constexpr std::uint32_t kImageTlsIndex = 0x20;
        *reinterpret_cast<std::uint32_t*>(0x146deebd4ULL) = kImageTlsIndex;
        if (tlsArray && runtime_tls_block.empty())
            runtime_tls_block.assign(runtime_tls_template);
        if (tlsArray && !runtime_tls_block.empty())
            tlsArray[kImageTlsIndex] = runtime_tls_block.data();
        std::fprintf(stderr, "[TLS] index=%u block=%p template=%zu\\n",
                     (unsigned)kImageTlsIndex,
                     runtime_tls_block.empty() ? nullptr : runtime_tls_block.data(),
                     runtime_tls_template.size());
    }

    // MSVC /guard:cf indirect-call slot (__guard_dispatch_icall_fptr,
    // 0x145d40858) holds a file image value that is an unrelocated RVA
    // into .rdata; native callers do `call [slot]` with the real target
    // in rax and expect the slot to be a jmp-rax trampoline.  Install a
    // translating trampoline: if rax is a small RVA that maps into the
    // fixed image, add the image base first, then jump.'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('TLS array takeover added')
