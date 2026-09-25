cmake_minimum_required(VERSION 3.16)
project(centrifuge LANGUAGES CXX)

include(CTest)
find_package(Threads REQUIRED)

option(CENTRIFUGE_ENABLE_SANITIZERS
       "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(CENTRIFUGE_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
set(CENTRIFUGE_BENCHMARK_MANIFEST
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmark_manifest.json"
    CACHE FILEPATH "Linux/Windows decompiler quality benchmark manifest")
set(CENTRIFUGE_BLENDER_WINDOWS_BINARY "" CACHE FILEPATH
    "Optional path to a pinned Windows x64 blender.exe scale fixture")
set(CENTRIFUGE_BLENDER_WINDOWS_MANIFEST
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/blender_windows_manifest.json"
    CACHE FILEPATH "Manifest for the Blender Windows scale fixture")
set(CENTRIFUGE_BLENDER_WINDOWS_OUTPUT
    "${CMAKE_CURRENT_BINARY_DIR}/blender-recovery"
    CACHE PATH "Output directory for the Blender recovery benchmark")
set(CENTRIFUGE_KRITA_WINDOWS_BINARY "" CACHE FILEPATH
    "Optional path to a pinned Windows x64 libkritaui.dll scale fixture")
set(CENTRIFUGE_KRITA_WINDOWS_MANIFEST
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/krita_windows_manifest_6_0_3.json"
    CACHE FILEPATH "Manifest for the Krita Windows scale fixture")
set(CENTRIFUGE_KRITA_WINDOWS_OUTPUT
    "${CMAKE_CURRENT_BINARY_DIR}/krita-recovery"
    CACHE PATH "Output directory for the Krita recovery benchmark")

if(CENTRIFUGE_BUILD_FUZZERS AND NOT CENTRIFUGE_ENABLE_SANITIZERS)
  message(FATAL_ERROR
    "CENTRIFUGE_BUILD_FUZZERS requires CENTRIFUGE_ENABLE_SANITIZERS=ON")
endif()
if(CENTRIFUGE_BUILD_FUZZERS AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "CENTRIFUGE_BUILD_FUZZERS requires Clang")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(centrifuge_core STATIC
  src/memory.cpp
  src/loader.cpp
  src/loader_elf.cpp
  src/loader_pe.cpp
  src/disasm.cpp
  src/disasm_x86.cpp
  src/disasm_riscv.cpp
  src/pcode.cpp
  src/sleigh.cpp
  src/cfg.cpp
  src/decompile.cpp
  src/analysis.cpp
  src/midir.cpp
  src/highir.cpp
  src/cpp_recovery.cpp
  src/stack_recovery.cpp
  src/symbolic.cpp
  src/calling_convention.cpp
  src/import_prototype.cpp
  src/global_recovery.cpp
  src/program_graph.cpp
  src/project_recovery.cpp
  src/semantic_coverage.cpp
  src/ir.cpp
)
target_include_directories(centrifuge_core PUBLIC include)
target_link_libraries(centrifuge_core PUBLIC Threads::Threads)

if(CENTRIFUGE_ENABLE_SANITIZERS)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    include(CheckCXXSourceCompiles)
    set(_centrifuge_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
    set(CMAKE_REQUIRED_FLAGS
        "${CMAKE_REQUIRED_FLAGS} -fsanitize=address,undefined")
    check_cxx_source_compiles(
      "int main() { return 0; }"
      CENTRIFUGE_SANITIZER_RUNTIME_AVAILABLE
    )
    set(CMAKE_REQUIRED_FLAGS "${_centrifuge_saved_required_flags}")
    unset(_centrifuge_saved_required_flags)
    if(NOT CENTRIFUGE_SANITIZER_RUNTIME_AVAILABLE)
      message(FATAL_ERROR
        "The selected compiler cannot link the ASan/UBSan runtimes. "
        "Install the sanitizer runtime libraries or configure with a "
        "Clang/GCC toolchain that provides them.")
    endif()
    target_compile_options(centrifuge_core PUBLIC
      -fsanitize=address,undefined
      -fno-omit-frame-pointer
    )
    target_link_options(centrifuge_core PUBLIC
      -fsanitize=address,undefined
    )
  else()
    message(FATAL_ERROR
      "CENTRIFUGE_ENABLE_SANITIZERS requires GCC or Clang")
  endif()
endif()

add_executable(centrifuge src/cli/main.cpp)
target_link_libraries(centrifuge PRIVATE centrifuge_core)
# decompile() recursively walks long straight-line CFG chains; each
# recursion frame carries a large BlockEmitter plus lambdas.  Blender 5.x
# contains functions whose block depth exhausts the default 1MB main-thread
# stack (crash inside malloc).  Give every executable a 16MB stack.
if(MSVC)
  target_link_options(centrifuge PRIVATE /STACK:16777216)
else()
  target_link_options(centrifuge PRIVATE -Wl,--stack,16777216)
endif()

# Test-sample generator (pure C++, writes ELF32/ELF64/PE32+ test binaries)
add_executable(make_samples tools/make_samples.cpp)

# SLEIGH-lite engine + p-code interpreter unit tests
add_executable(test_sleigh tests/test_sleigh.cpp)
target_link_libraries(test_sleigh PRIVATE centrifuge_core)

add_executable(test_x86_flags tests/test_x86_flags.cpp)
target_link_libraries(test_x86_flags PRIVATE centrifuge_core)

add_executable(test_ir tests/test_ir.cpp)
target_link_libraries(test_ir PRIVATE centrifuge_core)

add_executable(test_loaders tests/test_loaders.cpp)
target_link_libraries(test_loaders PRIVATE centrifuge_core)

add_executable(test_stack_recovery tests/test_stack_recovery.cpp)
target_link_libraries(test_stack_recovery PRIVATE centrifuge_core)

add_executable(test_calling_convention tests/test_calling_convention.cpp)
target_link_libraries(test_calling_convention PRIVATE centrifuge_core)

add_executable(test_type_recovery tests/test_type_recovery.cpp)
target_link_libraries(test_type_recovery PRIVATE centrifuge_core)

add_executable(test_global_recovery tests/test_global_recovery.cpp)
target_link_libraries(test_global_recovery PRIVATE centrifuge_core)

add_executable(test_control_flow tests/test_control_flow.cpp)
target_link_libraries(test_control_flow PRIVATE centrifuge_core)

add_executable(test_trampoline tests/test_trampoline.cpp)
target_link_libraries(test_trampoline PRIVATE centrifuge_core)

if(CENTRIFUGE_BUILD_FUZZERS)
  add_executable(fuzz_loader fuzz/loader_fuzz.cpp)
  target_link_libraries(fuzz_loader PRIVATE centrifuge_core)
  target_compile_options(fuzz_loader PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_loader PRIVATE
    -fsanitize=fuzzer,address,undefined
  )
endif()

if(BUILD_TESTING)
  add_test(
    NAME sleigh_unit
    COMMAND test_sleigh
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/riscv64.slaspec"
  )
  set_tests_properties(sleigh_unit PROPERTIES LABELS "unit")

  add_test(
    NAME x86_flags
    COMMAND test_x86_flags
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/x86-64.slaspec"
  )
  set_tests_properties(x86_flags PROPERTIES LABELS "unit;x86")

  add_test(NAME function_ir COMMAND test_ir)
  set_tests_properties(function_ir PROPERTIES LABELS "unit;analysis")

  add_test(
    NAME stack_recovery
    COMMAND test_stack_recovery
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/x86-64.slaspec"
  )
  set_tests_properties(stack_recovery PROPERTIES LABELS "unit;x86")

  add_test(
    NAME calling_convention
    COMMAND test_calling_convention
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/x86-64.slaspec"
  )
  set_tests_properties(calling_convention PROPERTIES LABELS "unit;x86")

  add_test(
    NAME type_recovery
    COMMAND test_type_recovery
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/x86-64.slaspec"
  )
  set_tests_properties(type_recovery PROPERTIES LABELS "unit;x86")

  add_test(
    NAME global_recovery
    COMMAND test_global_recovery
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/x86-64.slaspec"
  )
  set_tests_properties(global_recovery PROPERTIES LABELS "unit;x86")

  add_test(
    NAME control_flow
    COMMAND test_control_flow
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/riscv64.slaspec"
  )
  set_tests_properties(control_flow PROPERTIES LABELS "unit;riscv")

  add_test(
    NAME trampoline
    COMMAND test_trampoline
            "${CMAKE_CURRENT_SOURCE_DIR}/sleigh/x86-64.slaspec"
  )
  set_tests_properties(trampoline PROPERTIES LABELS "unit;x86")

  add_test(
    NAME loader_malformed
    COMMAND test_loaders
            "${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_elf32"
            "${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_elf64"
            "${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_pe64.exe"
  )
  set_tests_properties(loader_malformed PROPERTIES LABELS "unit;loader")

  find_package(Python3 COMPONENTS Interpreter)
  find_program(CENTRIFUGE_C_COMPILER NAMES gcc clang cc)
  if(Python3_Interpreter_FOUND AND CENTRIFUGE_C_COMPILER)
    add_test(
      NAME decompiler_roundtrip
      COMMAND "${Python3_EXECUTABLE}"
              "${CMAKE_CURRENT_SOURCE_DIR}/tests/roundtrip.py"
              --centrifuge "$<TARGET_FILE:centrifuge>"
              --source-dir "${CMAKE_CURRENT_SOURCE_DIR}"
              --cc "${CENTRIFUGE_C_COMPILER}"
    )
    set_tests_properties(decompiler_roundtrip PROPERTIES
      LABELS "integration"
      TIMEOUT 60
    )
    add_test(
      NAME decompiler_large_differential
      COMMAND "${Python3_EXECUTABLE}"
              "${CMAKE_CURRENT_SOURCE_DIR}/tests/roundtrip.py"
              --centrifuge "$<TARGET_FILE:centrifuge>"
              --source-dir "${CMAKE_CURRENT_SOURCE_DIR}"
              --cc "${CENTRIFUGE_C_COMPILER}"
              --large
    )
    set_tests_properties(decompiler_large_differential PROPERTIES
      LABELS "integration;differential;large"
      TIMEOUT 180
    )
    find_program(CENTRIFUGE_OBJDUMP NAMES objdump llvm-objdump)
    set(CENTRIFUGE_X86_ORACLE_ARGS)
    if(CENTRIFUGE_OBJDUMP)
      list(APPEND CENTRIFUGE_X86_ORACLE_ARGS --objdump "${CENTRIFUGE_OBJDUMP}")
    endif()
    add_test(NAME decompiler_x86_roundtrip
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/x86_roundtrip.py"
              --centrifuge "$<TARGET_FILE:centrifuge>"
              --source-dir "${CMAKE_CURRENT_SOURCE_DIR}" --cc "${CENTRIFUGE_C_COMPILER}"
              ${CENTRIFUGE_X86_ORACLE_ARGS})
    set_tests_properties(decompiler_x86_roundtrip PROPERTIES
      LABELS "integration;differential;x86" TIMEOUT 180)
  else()
    message(STATUS
      "Skipping decompiler_roundtrip: Python 3 and a C compiler are required")
  endif()
  if(Python3_Interpreter_FOUND)
    add_test(
      NAME project_recovery_smoke
      COMMAND "${Python3_EXECUTABLE}"
              "${CMAKE_CURRENT_SOURCE_DIR}/tests/project_recovery_smoke.py"
              --centrifuge "$<TARGET_FILE:centrifuge>"
              --source-dir "${CMAKE_CURRENT_SOURCE_DIR}"
              --cmake "${CMAKE_COMMAND}"
    )
    set_tests_properties(project_recovery_smoke PROPERTIES
      LABELS "integration;project-recovery;recompilation;windows"
      TIMEOUT 180
    )
    add_test(
      NAME decompiler_quality_benchmark
      COMMAND "${Python3_EXECUTABLE}"
              "${CMAKE_CURRENT_SOURCE_DIR}/tests/quality_benchmark.py"
              --centrifuge "$<TARGET_FILE:centrifuge>"
              --source-dir "${CMAKE_CURRENT_SOURCE_DIR}"
              --manifest "${CENTRIFUGE_BENCHMARK_MANIFEST}"
              --output "${CMAKE_CURRENT_BINARY_DIR}/quality-benchmark.json"
    )
    set_tests_properties(decompiler_quality_benchmark PROPERTIES
      LABELS "integration;benchmark;linux;windows"
      TIMEOUT 180
    )
    if(CENTRIFUGE_BLENDER_WINDOWS_BINARY AND
       EXISTS "${CENTRIFUGE_BLENDER_WINDOWS_BINARY}")
      add_test(
        NAME blender_windows_project_recovery
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/blender_windows_recovery.py"
                --centrifuge "$<TARGET_FILE:centrifuge>"
                --source-dir "${CMAKE_CURRENT_SOURCE_DIR}"
                --binary "${CENTRIFUGE_BLENDER_WINDOWS_BINARY}"
                --manifest "${CENTRIFUGE_BLENDER_WINDOWS_MANIFEST}"
                --output-dir "${CENTRIFUGE_BLENDER_WINDOWS_OUTPUT}"
                --report-name "blender_recovery_report.json"
                --cmake "${CMAKE_COMMAND}"
      )
      set_tests_properties(blender_windows_project_recovery PROPERTIES
        LABELS "integration;benchmark;large;windows;blender;project-recovery"
        TIMEOUT 3600
      )
    else()
      message(STATUS
        "Blender recovery benchmark disabled; set "
        "CENTRIFUGE_BLENDER_WINDOWS_BINARY to blender.exe")
    endif()
    if(CENTRIFUGE_KRITA_WINDOWS_BINARY AND
       EXISTS "${CENTRIFUGE_KRITA_WINDOWS_BINARY}")
      add_test(
        NAME krita_windows_project_recovery
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/blender_windows_recovery.py"
                --centrifuge "$<TARGET_FILE:centrifuge>"
                --source-dir "${CMAKE_CURRENT_SOURCE_DIR}"
                --binary "${CENTRIFUGE_KRITA_WINDOWS_BINARY}"
                --manifest "${CENTRIFUGE_KRITA_WINDOWS_MANIFEST}"
                --output-dir "${CENTRIFUGE_KRITA_WINDOWS_OUTPUT}"
                --report-name "krita_recovery_report.json"
                --cmake "${CMAKE_COMMAND}"
      )
      set_tests_properties(krita_windows_project_recovery PROPERTIES
        LABELS "integration;benchmark;large;windows;krita;project-recovery"
        TIMEOUT 3600
      )
    else()
      message(STATUS
        "Krita recovery benchmark disabled; set "
        "CENTRIFUGE_KRITA_WINDOWS_BINARY to libkritaui.dll")
    endif()
  endif()
endif()
