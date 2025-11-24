cmake_minimum_required(VERSION 3.20)
project(EncryptionBenchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")

# Create executable
add_executable(EncryptionBenchmark src/main.cpp src/aes.c src/aes.h src/chacha20.cpp src/chacha20.h)

# Link math library (optional, for portable float operations)
target_link_libraries(EncryptionBenchmark m)