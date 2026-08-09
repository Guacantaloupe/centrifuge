cmake_minimum_required(VERSION 3.16)
project(ghra LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(ghra_core STATIC
  src/memory.cpp
  src/loader.cpp
  src/loader_elf.cpp
  src/loader_pe.cpp
  src/disasm.cpp
  src/disasm_x86.cpp
  src/disasm_riscv.cpp
  src/pcode.cpp
  src/sleigh.cpp
  src/analysis.cpp
)
target_include_directories(ghra_core PUBLIC include)

add_executable(ghra src/cli/main.cpp)
target_link_libraries(ghra PRIVATE ghra_core)

# Test-sample generator (pure C++, writes ELF32/ELF64/PE32+ test binaries)
add_executable(make_samples tools/make_samples.cpp)

# SLEIGH-lite engine + p-code interpreter unit tests
add_executable(test_sleigh tests/test_sleigh.cpp)
target_link_libraries(test_sleigh PRIVATE ghra_core)
