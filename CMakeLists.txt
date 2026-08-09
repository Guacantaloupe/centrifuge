cmake_minimum_required(VERSION 3.16)
project(ghra LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(GHRA_USE_CAPSTONE "Build with the Capstone disassembly backend" ON)

add_library(ghra_core STATIC
  src/memory.cpp
  src/loader.cpp
  src/loader_elf.cpp
  src/loader_pe.cpp
  src/disasm.cpp
  src/analysis.cpp
)
target_include_directories(ghra_core PUBLIC include)

set(GHRA_CAPSTONE_FOUND FALSE)

if(GHRA_USE_CAPSTONE)
  # 1) pkg-config (MSYS2/Homebrew/system packages)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(CAPSTONE QUIET capstone)
    if(CAPSTONE_FOUND)
      target_include_directories(ghra_core PRIVATE ${CAPSTONE_INCLUDE_DIRS})
      target_link_libraries(ghra_core PUBLIC ${CAPSTONE_LIBRARIES})
      target_compile_definitions(ghra_core PUBLIC GHRA_HAVE_CAPSTONE)
      set(GHRA_CAPSTONE_FOUND TRUE)
      message(STATUS "ghra: capstone found via pkg-config")
    endif()
  endif()
  # 2) build from source (needs network on first configure)
  if(NOT GHRA_CAPSTONE_FOUND)
    include(FetchContent)
    set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(capstone
      GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
      GIT_TAG 5.0.3)
    FetchContent_MakeAvailable(capstone)
    target_link_libraries(ghra_core PUBLIC capstone)
    target_compile_definitions(ghra_core PUBLIC GHRA_HAVE_CAPSTONE)
    set(GHRA_CAPSTONE_FOUND TRUE)
    message(STATUS "ghra: capstone built from source")
  endif()
endif()

add_executable(ghra src/cli/main.cpp)
target_link_libraries(ghra PRIVATE ghra_core)
