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
centrifuge spec <spec.slaspec> <file> analyze-all [abi]
centrifuge spec <spec.slaspec> <file> midir <addr> [end] [abi]
centrifuge spec <spec.slaspec> <file> highir <addr> [end]
centrifuge spec <spec.slaspec> <file> cpp-types
centrifuge spec <spec.slaspec> <file> semantic-coverage
centrifuge spec <spec.slaspec> <file> decompile-typed <addr> [abi]
centrifuge spec <spec.slaspec> <file> knowledge-graph [output.json] [abi]
centrifuge spec <spec.slaspec> <file> recover-project <output-dir> [abi] [max-functions]
centrifuge spec <spec.slaspec> <file> disasm|funcs|pcode|cfg|analyze|decompile
```

## Architecture

```
src/cli/main.cpp        CLI front end
src/loader.cpp          format dispatch (magic sniffing)
src/loader_elf.cpp      ELF32/ELF64 loader (segments, sections, symbols)
src/loader_pe.cpp       PE32/PE32+ loader (sections, imports/delay imports,
                         exports, resources, unwind data, real entry point)
src/disasm.cpp          Disassembler abstraction + builtin backends
src/disasm_x86.cpp      hand-written x86 / x86-64 decoder
src/disasm_riscv.cpp    hand-written RV32I/RV64I + M + C decoder
src/pcode.cpp           p-code IR (varnodes, ops, interpreter)
src/sleigh.cpp          SLEIGH-lite: spec parser, pattern matcher, p-code emitter
src/cfg.cpp             CFG construction + iterative dominators
src/midir.cpp           verified SSA MidIR + object/range alias analysis
src/highir.cpp           structured AST (loops, switch, irreducible SCCs)
src/cpp_recovery.cpp     C++ object graph: RTTI/vtables, this/vptr propagation,
                         methods, fields/layout, lifetime, runtime operations,
                         member pointers, thunks, and cross-module merging
src/program_graph.cpp     unified functions/types/classes/objects/calls graph
src/project_recovery.cpp  recompilable C++/CMake project and report generation
src/semantic_coverage.cpp executable-image ISA semantic coverage audit and
constructor-level proof inventory (empty constructors remain explicitly
unproven; exception guards never count as instruction semantics)
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

## Windows Blender scale benchmark

The opt-in benchmark is pinned to the official Blender 4.2.0 Windows x64
portable archive and verifies its SHA-256 before extraction:

```powershell
$blender = .\tests\fetch_blender_windows.ps1
cmake -S . -B build-blender `
  -DCENTRIFUGE_BLENDER_WINDOWS_BINARY="$blender"
cmake --build build-blender --config Release
ctest --test-dir build-blender -C Release -R blender_windows --output-on-failure
```

This gate currently proves large-PE loading, recovery, C++ project generation,
compilation, linking, and verifier execution. The recovered project preserves
the PE import/DLL inventory, exact initialized global-data regions, individual
resource payloads, and a callable wrapper for `AddressOfEntryPoint`. The pinned
Blender fixture requires zero unresolved code-generation markers. Its JSON
report deliberately
keeps `semantic_equivalence_verified` false until Blender startup/render trace
replay is implemented; a successful compile is not treated as behavioral
equivalence.

`recover-project` emits `imports.json`, `globals.json` plus
`data/globals.bin`, `resources/index.json` plus exact resource payloads,
`entrypoint.json`, and `recovered_metadata.hpp/.cpp` in addition to recovered
function sources and the program knowledge graph.

Partitioned MemorySSA assigns independent versions to proven-disjoint stack,
global, heap, parameter, and aggregate-field locations. `analyze-all` computes
local Mod/Ref summaries and propagates them to a fixed point over the call
graph, including recursion.

The cross-platform quality benchmark is manifest driven. Replace the default
manifest with a larger Linux/Windows corpus without changing the runner:

```sh
python tests/quality_benchmark.py --centrifuge build/centrifuge \
  --source-dir . --manifest tests/benchmark_manifest.json \
  --output quality-benchmark.json
cmake -S . -B build-corpus \
  -DCENTRIFUGE_BENCHMARK_MANIFEST=/path/to/large-corpus.json
```

The benchmark runner also accepts recursive Linux/Windows corpus globs and a
previous JSON baseline.  Regressions in typed output, unresolved operations,
decode failures, or empty semantics fail the run:

```sh
python tests/quality_benchmark.py --centrifuge build/centrifuge \
  --source-dir . --manifest tests/large_corpus_manifest.example.json \
  --baseline previous-quality.json --output quality-benchmark.json \
  --timeout 300
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
- `tests/test_x86_flags.cpp`: Intel SHA-1/SHA-256, AES/VAES, GFNI affine and
  inverse-affine, PCLMUL/VPCLMUL hardware/reference vectors; CPUID, CPL,
  CR0/CR4/XCR0 #UD/#NM/#GP/#MF gates; x87 exception and precision-control
  boundaries.
- `semantic-coverage` prints both executable-image coverage and a constructor
  proof inventory. Empty declarations are never counted as proved merely
  because an exception guard exists; the current unproven count is expected
  to decrease as long-tail encodings receive shared providers and vectors.
