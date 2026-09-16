# Correctness check, 2026-09-16

## Scope

Reviewed the recent native-emitter changes, call and implicit-register writes,
scalar extraction, memory-image bounds, ELF range checks, and the differential
test harness. The standard CTest suite covers loaders, SLEIGH, SSA, stack and
type recovery, calling conventions, globals, control flow, trampolines,
RISC-V and x86 recompilation, and generated PE project compilation/execution.

## Repairs

- Discard cached register expressions/constants after calls so subsequent
  returns and arguments cannot reuse pre-call definitions. Capture call
  argument expressions before invalidation.
- Discard expressions after x86 string instructions and invalidate affected
  entry-parameter aliases. LODSQ now returns the loaded value rather than a
  previously recorded RAX expression.
- Guard scalar SUBPIECE byte offsets before shifting. Offsets of eight or
  more yield zero, matching the scalar evaluator; dynamic offsets cannot
  cause a shift of 64 bits or more. Nonzero shifts use an unsigned source.
- Keep zero-offset extraction as a plain width cast.

## Reproduction

Finish the build before starting CTest: Windows cannot replace a running test
executable during linking.

```sh
cmake --build build -j 4
ctest --test-dir build --output-on-failure -E 'blender_windows|krita_windows' -j 4
```

The x86 differential corpus contains 53 functions when objdump is available,
including seven compiler-generated leaf functions. It compares returns and
eight bytes of memory at three optimization levels. These finite vectors do
not establish general semantic equivalence.

## Remaining validation

Final standard-suite result: 15/15 passed. The 53-function x86 corpus passed
9,171,968 return/memory comparisons per optimization level, or 27,515,904
across `-O0`, `-O2`, and `-O3`. The build completed successfully before testing.

The optional Blender and Krita recovery gates are separate from the standard
suite above and have not been rerun for these repairs. They verify generation,
compilation and execution of a recovery verifier, not full application behavior.
Run them with the configured fixture paths using:

```sh
ctest --test-dir build --output-on-failure -R 'blender_windows|krita_windows'
```

Application startup/render trace comparison, multithreaded atomicity, and
general exception equivalence remain outside the current differential corpus.
