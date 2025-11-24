cmake_minimum_required(VERSION 3.20)
project(EncryptionBenchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")

# Add libsodium include directory
include_directories(${PROJECT_SOURCE_DIR}/external/libsodium/include)

# Create executable
add_executable(
    EncryptionBenchmark
    src/main.cpp
    src/aes.c src/aes.h
    src/chacha20.cpp src/chacha20.h
    src/chacha20_sodium.cpp src/chacha20_sodium.h
    src/chacha20poly1305.cpp src/chacha20poly1305.h
    src/aes_sodium.cpp src/aes_sodium.h
)

# Link libsodium (static) and math library
target_link_libraries(
    EncryptionBenchmark
    ${PROJECT_SOURCE_DIR}/external/libsodium/lib/libsodium.a
    m
)
