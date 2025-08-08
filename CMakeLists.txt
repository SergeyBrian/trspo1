cmake_minimum_required(VERSION 3.26)
project(monitor CXX)

if (MSVC)
  enable_language(ASM_MASM)
else()
  enable_language(ASM)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone
    GIT_TAG        6.0.0-Alpha3
)

FetchContent_MakeAvailable(capstone)


if (WIN32)
set(hook_sources
    src/hook/manager/manager.cpp
    src/hook/patch/patch.cpp
    src/hook/hooks/filter.cpp
    src/hook/hooks/logger.cpp 
)
add_executable(test test/test.cpp)
add_executable(patch_test ${hook_sources} test/patch_test.cpp)
add_library(hook SHARED ${hook_sources} src/hook/hooks/tcp_logger.cpp src/hook/dllmain.cpp)
add_library(net_tcp
    src/common/internal/tcp_win.cpp
)
set(injector_sources 
    src/injector/utils_win.cpp
    src/injector/injector.cpp
)

else()
set(hook_sources
    src/hook/manager/manager_unix.cpp
    src/hook/patch/patch_unix.cpp
    src/hook/hooks/filter_unix.cpp
)
add_executable(test test/test_unix.cpp)
add_executable(patch_test ${hook_sources} test/patch_test_unix.cpp)
add_library(hook SHARED ${hook_sources} src/hook/hooks/tcp_logger_unix.cpp src/hook/shared_init.cpp)
add_library(net_tcp
    src/common/internal/tcp_unix.cpp
)
set(injector_sources 
    src/injector/utils_unix.cpp
    src/injector/injector.cpp
)

endif()

add_executable(${CMAKE_PROJECT_NAME} ${injector_sources} src/main.cpp)

if (WIN32)
    target_link_libraries(net_tcp PUBLIC ws2_32)
    target_sources(hook PRIVATE src/hook/hooks/common.asm)
    target_sources(patch_test PRIVATE src/hook/hooks/common.asm)
endif()

target_link_libraries(monitor PRIVATE capstone net_tcp)
target_link_libraries(hook PRIVATE capstone net_tcp)

target_link_libraries(patch_test PRIVATE capstone)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

