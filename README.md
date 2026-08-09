# ghra — a Ghidra reimplementation in C++17 (100% C++)

Ghidra (NSA) is a reverse-engineering suite: file loaders, a *Sleigh*
spec-driven disassembler, a decompiler, analysis passes, a GUI, and a
scripting API. `ghra` reimplements that architecture in C++17, one layer at a
time, with **zero external dependencies** — no Capstone, no LLVM, no libopcodes.
All loaders, disassemblers and analysis are written from scratch in C++17.

## Status (v0.2)

| Layer            | Ghidra equivalent | ghra status |
|------------------|-------------------|-------------|
| Memory model     | Address space / program image | ✅ `MemoryImage` |
| Loaders          | `LoaderService` (ELF, PE, ...) | ✅ ELF32/ELF64, PE32/PE32+ |
| Symbol table     | Symbol table / exports         | ✅ symtab+dynsym, PE exports |
| Disassembler     | Sleigh + language modules      | ✅ hand-written x86/x86-64 + RISC-V decoders (pure C++) |
| Function discovery | `FunctionAnalyzer`           | 🟡 symbol seeds + recursive-descent scan |
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
src/analysis.cpp        function discovery pass
tools/make_samples.cpp  C++ test-binary generator (no Python, no assembler)
include/ghra/*.hpp      public API (memory, loader, disasm, analysis)
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

## Validation

The decoders are validated instruction-by-instruction against GNU binutils
objdump (an independent decoder):

- notepad.exe: 600 instructions — 0 byte errors, 0 boundary mismatches
- kernel32.dll: 1750 instructions — 0 byte errors, 0 boundary mismatches
- real RISC-V ELF (riscv64-unknown-elf-gcc output): identical to objdump,
  including compressed (C ext) instructions

The x86 decoder covers the common legacy integer/branch/SSE system
instruction set (exact lengths). VEX/EVEX and x87 are not decoded yet — the
sweep stops there until the Sleigh milestone lands.

## Tests

`tools/make_samples.cpp` writes hand-crafted ELF32, ELF64 and PE32+ samples
(bytes written explicitly — no assembler dependency) so the loaders can be
verified deterministically. See ROADMAP.md for the full plan.
