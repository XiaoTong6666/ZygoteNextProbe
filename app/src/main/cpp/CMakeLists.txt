cmake_minimum_required(VERSION 3.22.1)
project(zygotenextprobe_native)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(main SHARED probe.cpp)
target_compile_options(main PRIVATE -O2 -Wall)
