cmake_minimum_required(VERSION 3.1.3)
project(
  ffsst
  LANGUAGES C CXX
  VERSION 0.1.0)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

option(BUILD_EXAMPLES "Build the ffsst command line tool." ON)

find_package(Threads REQUIRED)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Build type: Release, Debug or RelWithDebInfo" FORCE)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)
if(COMPILER_SUPPORTS_MARCH_NATIVE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
endif()

add_library(ffsst ffsst.cc dec.cc)
add_executable(binary codec.cc)
target_link_libraries (binary LINK_PUBLIC ffsst)
set_target_properties(binary PROPERTIES OUTPUT_NAME codec)
