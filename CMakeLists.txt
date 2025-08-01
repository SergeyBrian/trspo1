cmake_minimum_required(VERSION 3.26)
project(monitor CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(injector_sources 
    src/patch.cpp
    src/hook_manager.cpp
    src/injector.cpp
    src/hook.cpp
    src/hook.asm
)

set(hook_sources
    src/hook_dll.cpp
)

add_executable(${CMAKE_PROJECT_NAME} ${injector_sources} src/main.cpp)
add_executable(test ${injector_sources} test/test.cpp)
add_library(hook SHARED ${hook_sources})


