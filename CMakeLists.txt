cmake_minimum_required(VERSION 3.24)
project(atomic_swap)

set(CMAKE_CXX_STANDARD 17)
#设置为x86


set(secp256k1_lib_dir ${PROJECT_SOURCE_DIR}/third/secp256k1-zkp/.libs)

set(header_dir ${PROJECT_SOURCE_DIR}/header
        ${PROJECT_SOURCE_DIR}/third/secp256k1-zkp/include
        ${PROJECT_SOURCE_DIR}/third/secp256k1-zkp/src
        )
include_directories(
        ${header_dir})
set(PROJECT_SOURCES main.cpp
        header/utils.h )
link_directories(${secp256k1_lib_dir})
add_executable(atomic_swap ${PROJECT_SOURCES})

target_link_libraries(atomic_swap  secp256k1)
