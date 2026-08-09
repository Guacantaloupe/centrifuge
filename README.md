# ghra — a Ghidra reimplementation in C++17 (100% C++)

Ghidra (NSA) is a reverse-engineering suite: file loaders, a *Sleigh*
spec-driven disassembler, a decompiler, analysis passes, a GUI, and a
scripting API. `ghra` reimplements that architecture in C++17, one layer at a
time, with **zero external dependencies** — no Capstone, no LLVM, no libopcodes.
All loaders, disassemblers and analysis are written from scratch in C++17.

## Status (v0.3 part 1)

| Layer            | Ghidra equivalent | ghra status |
|------------------|-------------------|-------------|
| Memory model     | Address space / program image | ✅ `MemoryImage` |
| Loaders          | `LoaderService` (ELF, PE, ...) | ✅ ELF32/ELF64, PE32/PE32+ |
| Symbol table     | Symbol table / exports         | ✅ symtab+dynsym, PE exports |
| Disassembler     | Sleigh + language modules      | ✅ hand-written x86/x86-64 + RISC-V **and** SLEIGH-lite spec engine (p-code) |
| p-code           | `PcodeOps` / varnodes          | ✅ `PcodeInsn` + interpreter (constant folding + concrete eval) |
| Function discovery | `FunctionAnalyzer`           | 🟡 symbol seeds + recursive-descent scan (works on both backends) |
| Decompiler       | `DecompInterface` (p-code → C) | ⛔ next milestone |
| GUI              | Ghidra window                  | ⛔ later (ImGui/Qt) |

## Building

Requires CMake ≥ 3.16 and a C++17 compiler. Nothing else.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Usage

```
ghra <file> info               # format, arch, entry, sections, symbols
ghra <file> funcs              # discovered functions
ghra <file> disasm <addr> [n]  # disassemble n instructions
ghra <file> dump <addr> <size> # hexdump
ghra spec <spec.slaspec> <file> disasm <addr> [n]  # spec-driven disasm
ghra spec <spec.slaspec> <file> funcs             # analysis via spec engine
ghra spec <spec.slaspec> <file> pcode <addr> [n]  # Ghidra-style p-code IR
```

Example:

```
$ ghra samples/sample_elf64 funcs
backend:   builtin-c++ (x86-64)
FUNCTIONS (2)
name                     addr                 size       src
main                     0x00401000           0x10       sym
helper                   0x00401020           0x0C       sym
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
sleigh/riscv64.slaspec  RISC-V RV64IM language module (spec data, not code)
src/analysis.cpp        function discovery pass
tools/make_samples.cpp  C++ test-binary generator (no Python, no assembler)
include/ghra/*.hpp      public API (memory, loader, disasm, pcode, sleigh, analysis)
```

Design notes:

- The loader produces a `Program` — sections, symbols, entry point, and a flat
  `MemoryImage` of mapped, permission-tagged blocks. This is ghra's equivalent
  of Ghidra's program database, kept in memory for now.
- The `Disassembler` interface is where a Sleigh-style spec engine will plug
  in (ROADMAP v0.3). Today it is backed by hand-written decoders that emit
  exact instruction lengths plus branch/call targets for analysis. The raw
  fallback keeps the pipeline alive for not-yet-supported architectures.
- `findFunctions()` seeds from symbols/exports/entry, then recursive-descent
  scans, following direct calls (promoting targets to functions) and direct
  jumps. Sizes come from next-function distance.
- The SLEIGH-lite engine (`src/sleigh.cpp`) is the v0.3 milestone: it parses
  `.slaspec`-style specs (spaces, registers, tokens/fields, attach variables,
  constructors with bit patterns) and emits p-code with constant folding and
  branch-target resolution. `sleigh/riscv64.slaspec` is the first language
  module — new ISAs now mean writing a spec, not C++ tables.

## Validation

Decoders are validated instruction-by-instruction against GNU binutils
objdump (an independent decoder):

- hand-written x86-64: notepad.exe 600 insns + kernel32.dll 1750 insns —
  0 byte errors, 0 boundary mismatches
- hand-written RISC-V: matches objdump incl. compressed instructions
- SLEIGH-lite RISC-V spec: real compiler output (fib recursion, array
  loops, stack frames) — 120 insns, 0 mismatches vs objdump
- `tests/test_sleigh.cpp`: spec disassembly + p-code interpreter semantics
  (add/mulw/addi sign-extension/load/store/branch targets)

## Tests

`tools/make_samples.cpp` writes hand-crafted ELF32, ELF64 and PE32+ samples
(bytes written explicitly — no assembler dependency) so the loaders can be
verified deterministically. See ROADMAP.md for the full plan.
