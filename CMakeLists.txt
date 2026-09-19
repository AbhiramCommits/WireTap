cmake_minimum_required(VERSION 3.16)
project(wiretap LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WIRETAP_BUILD_TESTS "Build unit tests" ON)
option(WIRETAP_SANITIZE "Enable AddressSanitizer + UBSan" OFF)

set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CMAKE_CXX_FLAGS_RELEASE "-O2 -march=native")
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -march=native")
endif()

find_package(Threads REQUIRED)

add_library(wiretap
  src/decoder.cpp
  src/book_builder.cpp
  src/receiver.cpp)
target_include_directories(wiretap PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(wiretap PUBLIC -Wall -Wextra -Wpedantic)
target_link_libraries(wiretap PUBLIC Threads::Threads)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(wiretap PUBLIC _GNU_SOURCE)
endif()

if(WIRETAP_SANITIZE)
  target_compile_options(wiretap PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(wiretap PUBLIC -fsanitize=address,undefined)
endif()

add_executable(wiretap-dump src/main.cpp)
target_link_libraries(wiretap-dump PRIVATE wiretap)

add_executable(wiretap_recv src/wiretap_recv.cpp)
target_link_libraries(wiretap_recv PRIVATE wiretap)

if(WIRETAP_BUILD_TESTS)
  enable_testing()
  include(FetchContent)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  add_subdirectory(tests)
endif()
