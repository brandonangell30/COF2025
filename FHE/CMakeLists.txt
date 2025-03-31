cmake_minimum_required(VERSION 3.13)
project(seal_quadratic_example)

set(CMAKE_CXX_STANDARD 17)

# Set vcpkg toolchain file with your specific path
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../cofAttempt/vcpkg/scripts/buildsystems/vcpkg.cmake")

# Find Microsoft SEAL package
find_package(SEAL CONFIG REQUIRED)

# Add executable
add_executable(quadratic_fhe fhe.cpp)

# Link against Microsoft SEAL
target_link_libraries(quadratic_fhe PRIVATE SEAL::seal)