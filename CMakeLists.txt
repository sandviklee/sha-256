cmake_minimum_required(VERSION 3.29)
project(sha256 C)

set(CMAKE_C_STANDARD 99)

add_executable(sha256 src/main.c
        src/sha256.c
        src/sha256.h)
