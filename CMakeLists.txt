cmake_minimum_required(VERSION 3.26)
project(monitor CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone
    GIT_TAG        6.0.0-Alpha3
)

FetchContent_MakeAvailable(capstone)

set(injector_sources 
    src/injector/injector.cpp
)

set(hook_sources
    src/hook/manager/manager.cpp
    src/hook/patch/patch.cpp
    src/hook/hooks/filter.cpp
    src/hook/hooks/logger.cpp 
    src/hook/hooks/common.asm
)

add_executable(${CMAKE_PROJECT_NAME} ${injector_sources} src/main.cpp)
add_executable(test test/test.cpp)
add_executable(patch_test ${hook_sources} test/patch_test.cpp)
add_library(hook SHARED ${hook_sources} src/hook/hooks/tcp_logger.cpp src/hook/dllmain.cpp)

add_library(net_tcp
    src/common/internal/tcp_win.cpp
)

if (WIN32)
    target_link_libraries(net_tcp PUBLIC ws2_32)
endif()

target_link_libraries(monitor PRIVATE net_tcp)
target_link_libraries(hook PRIVATE capstone net_tcp)

target_link_libraries(patch_test PRIVATE capstone)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

