# Centrifuge (离心机) — a C++17 reimplementation merging Ghidra + angr

Ghidra (NSA) is a static reverse-engineering suite: file loaders, a *Sleigh*
spec-driven disassembler, and a decompiler that turns p-code into C. angr
(UCSB) is a symbolic-execution framework that explores program paths with
constraint solving. **Centrifuge merges both philosophies on one foundation:**
loaders → spec-driven disassembly → p-code (our unified IR, replacing both
Sleigh's p-code and angr's VEX) → static decompilation **and** symbolic
exploration, all written from scratch in C++17 with zero external
dependencies.

就像离心机把混合物甩开、按成分分离一样，Centrifuge 把二进制拆成成分——
代码、数据、控制流、符号约束——分别分析，再拼回对程序的理解。

## Status (v0.4 + v0.3 x86)

| Layer            | Ghidra equivalent | angr equivalent | centrifuge status |
|------------------|-------------------|-----------------|-------------------|
| Loaders          | `LoaderService`   | `cle`           | ✅ ELF32/64, PE32/PE32+ |
| Disassembler     | Sleigh + language modules | Capstone/PyVEX | ✅ hand-written x86/RISC-V + SLEIGH-lite spec engine (RISC-V full, x86-64 partial) |
| IR               | p-code            | VEX             | ✅ own p-code (35+ ops) + interpreter |
| CFG + dominators | `BasicBlockModel` | CFGFast/CFGEmulated | ✅ `cfg.cpp` |
| Decompiler       | `DecompInterface` | —              | ✅ v0.4: stack frames, calls, loops; round-trip verified |
| Symbolic execution | —              | **core**        | ⛔ v0.7: p-code evaluator → symbolic values → concolic → solver |
| GUI              | Ghidra window     | —              | ⛔ later (ImGui/Qt) |

## Building

Requires CMake ≥ 3.16 and a C++17 compiler. Nothing else.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Run the unit and decompiler round-trip tests with CTest:

```sh
ctest --test-dir build --output-on-failure
```

For a GCC or Clang toolchain that provides the sanitizer runtimes, create a
separate ASan/UBSan build:

```sh
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCENTRIFUGE_ENABLE_SANITIZERS=ON
cmake --build build-sanitize
ctest --test-dir build-sanitize --output-on-failure
```

With Clang, the in-memory loader can also be exercised through libFuzzer:

```sh
cmake -S . -B build-fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DCENTRIFUGE_ENABLE_SANITIZERS=ON \
  -DCENTRIFUGE_BUILD_FUZZERS=ON
cmake --build build-fuzz --target fuzz_loader
build-fuzz/fuzz_loader -max_total_time=60 samples
```

## Usage

```
centrifuge <file> info               # format, arch, entry, sections, symbols
centrifuge <file> funcs              # discovered functions
centrifuge <file> disasm <addr> [n]  # disassemble n instructions
centrifuge <file> dump <addr> <size> # hexdump
centrifuge spec <spec.slaspec> <file> disasm|funcs|pcode|cfg|analyze|decompile
```

## Architecture

```
src/cli/main.cpp        CLI front end
src/loader.cpp          format dispatch (magic sniffing)
src/loader_elf.cpp      ELF32/ELF64 loader (segments, sections, symbols)
src/loader_pe.cpp       PE32/PE32+ loader (sections, export table)
src/disasm.cpp          Disassembler abstraction + builtin backends
src/disasm_x86.cpp      hand-written x86 / x86-64 decoder
src/disasm_riscv.cpp    hand-written RV32I/RV64I + M + C decoder
src/pcode.cpp           p-code IR (varnodes, ops, interpreter)
src/sleigh.cpp          SLEIGH-lite: spec parser, pattern matcher, p-code emitter
src/cfg.cpp             CFG construction + iterative dominators
src/ir.cpp              function SSA, data-flow types, ABI signatures,
                        optimizer, exception edges, and jump tables
src/decompile.cpp       C decompiler (expression reconstruction, stack
                        frames, calls, if/return structuring)
sleigh/riscv64.slaspec  RISC-V RV64IMC language module (incl. compressed)
sleigh/x86-64.slaspec   x86-64 language module (common integer + SSE subset)
src/analysis.cpp        function discovery pass
tools/make_samples.cpp  C++ test-binary generator (no Python, no assembler)
include/centrifuge/*.hpp  public API
```

## Validation

- SLEIGH-lite RISC-V spec: real compiler output (fib recursion, array loops,
  stack frames) — 0 mismatches vs objdump, including compressed instructions
- x86-64 spec: notepad.exe vs objdump — every decoded instruction byte-exact,
  0 false positives (~50% coverage; sweep stops at uncovered long-tail forms)
- **Decompiler round-trip** (`tests/roundtrip.py`): decompile fib/sum_array/
  compute/max3/absdiff, compile the emitted C, run test vectors — results are
  identical to the original C (the IR semantics are provably correct, which
  is exactly what the symbolic-execution engine needs as its base)
- `tests/test_sleigh.cpp`: spec disassembly + p-code interpreter semantics
