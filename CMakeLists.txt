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
    src/hook/dllmain.cpp
)

add_executable(${CMAKE_PROJECT_NAME} ${injector_sources} src/main.cpp)
add_executable(test ${injector_sources} test/test.cpp)
add_executable(patch_test ${hook_sources} test/patch_test.cpp)
add_library(hook SHARED ${hook_sources})

target_link_libraries(hook PRIVATE capstone)
target_link_libraries(patch_test PRIVATE capstone)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

