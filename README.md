# ghra — a Ghidra reimplementation in C++17

Ghidra (NSA) is a reverse-engineering suite: file loaders, a *Sleigh*
spec-driven disassembler, a decompiler, analysis passes, a GUI, and a
scripting API. `ghra` reimplements that architecture in C++17, one layer at a
time. This is the v0.1 foundation: it loads real binaries, lists symbols and
functions, and disassembles.

## Status (v0.1)

| Layer            | Ghidra equivalent | ghra status |
|------------------|-------------------|-------------|
| Memory model     | Address space / program image | ✅ `MemoryImage` |
| Loaders          | `LoaderService` (ELF, PE, ...) | ✅ ELF32/ELF64, PE32/PE32+ |
| Symbol table     | Symbol table / exports         | ✅ symtab+dynsym, PE exports |
| Disassembler     | Sleigh + language modules      | 🟡 framework + Capstone backend (raw fallback) |
| Function discovery | `FunctionAnalyzer`           | 🟡 symbol seeds + recursive-descent scan |
| Decompiler       | `DecompInterface` (p-code → C) | ⛔ next milestone |
| GUI              | Ghidra window                  | ⛔ later (ImGui/Qt) |

## Building

Requires CMake ≥ 3.16 and a C++17 compiler. Capstone is optional (recommended):
found via pkg-config, or fetched and built from source automatically.

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
backend:   capstone (x86-64)
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
src/analysis.cpp        function discovery pass
src/disasm.cpp          Disassembler interface + backends
include/ghra/*.hpp      public API (memory, loader, disasm, analysis)
```

Design notes:

- The loader produces a `Program` — sections, symbols, entry point, and a
  flat `MemoryImage` of mapped, permission-tagged blocks. This is ghra's
  equivalent of Ghidra's program database, kept in memory for now.
- The `Disassembler` interface is where Sleigh would plug in. Today it's
  backed by Capstone (with operand-detail → resolved branch targets). The raw
  fallback keeps every layer working without a decoder.
- `findFunctions()` seeds from symbols/exports/entry, then recursive-descent
  scans, following direct calls (promoting targets to functions) and direct
  jumps. Sizes come from next-function distance.

## Tests

`tests/make_samples.py` writes hand-crafted ELF32, ELF64 and PE32+ samples
(bytes written explicitly — no assembler dependency) so the loaders can be
verified deterministically. See ROADMAP.md for the full plan.
