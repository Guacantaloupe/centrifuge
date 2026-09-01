import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 在 reloc 循环结束后打印统计
old = '''            pos += blockSize;
        }
    }

    // Write resolved import addresses back into the fixed-image IAT'''
new = '''            pos += blockSize;
        }
        std::fprintf(stderr, "[RELOC-OK] applied %llu blocks, %llu bytes; guard=0x%llx reloc0=0x%llx\\n",
                     (unsigned long long)blocks,
                     (unsigned long long)pos,
                     (unsigned long long)(kRelocAddr ? *reinterpret_cast<std::uintptr_t*>(0x145d40858ULL) : 0),
                     (unsigned long long)(kRelocAddr ? *reinterpret_cast<std::uintptr_t*>(0x145d418c0ULL) : 0));
    }

    // Write resolved import addresses back into the fixed-image IAT'''
assert old in src
src = src.replace(old, new)
# 加 blocks 计数变量
old2 = '''        std::size_t pos = 0;
        while (pos + 8 <= kRelocSize) {'''
new2 = '''        std::size_t pos = 0;
        std::uint64_t blocks = 0;
        while (pos + 8 <= kRelocSize) {'''
assert old2 in src
src = src.replace(old2, new2)
old3 = '''            pos += blockSize;
        }
        std::fprintf'''
new3 = '''            pos += blockSize;
            ++blocks;
        }
        std::fprintf'''
assert old3 in src
src = src.replace(old3, new3)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('reloc stats added')
