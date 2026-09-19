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

# HdrHistogram_c for latency histograms.
include(FetchContent)
FetchContent_Declare(hdrhistogram
  GIT_REPOSITORY https://github.com/HdrHistogram/HdrHistogram_c.git
  GIT_TAG 0.11.8)
set(HDR_HISTOGRAM_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(HDR_HISTOGRAM_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(HDR_HISTOGRAM_BUILD_LOG OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(hdrhistogram)
if(TARGET hdr_histogram_static)
  set(WIRETAP_HDR_TARGET hdr_histogram_static)
elseif(TARGET hdr_histogram)
  set(WIRETAP_HDR_TARGET hdr_histogram)
else()
  message(FATAL_ERROR "HdrHistogram_c did not provide a library target")
endif()

add_library(wiretap
  src/decoder.cpp
  src/book_builder.cpp
  src/receiver.cpp
  src/time_base.cpp
  src/latency.cpp
  src/gap_tracker.cpp
  src/recovery_client.cpp)
target_include_directories(wiretap PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${hdrhistogram_SOURCE_DIR}/include)
target_compile_options(wiretap PUBLIC -Wall -Wextra -Wpedantic)
target_link_libraries(wiretap PUBLIC Threads::Threads ${WIRETAP_HDR_TARGET})
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

# -- Apache Arrow / Parquet archive support (optional) ----------------------
# The archive writer needs Arrow >= 8. If Arrow is not found, the handler
# builds without the archive/dashboard publishing (data layer disabled).
option(WIRETAP_BUILD_ARCHIVE "Build the Parquet archive writer (needs Arrow)" ON)
if(WIRETAP_BUILD_ARCHIVE)
  # Prefer a Homebrew Arrow on macOS over any conda-shipped one.
  if(APPLE AND EXISTS "/opt/homebrew/lib/cmake/Arrow/ArrowConfig.cmake")
    set(Arrow_DIR "/opt/homebrew/lib/cmake/Arrow")
    set(Parquet_DIR "/opt/homebrew/lib/cmake/Parquet")
  endif()
  find_package(Arrow CONFIG QUIET)
  if(Arrow_FOUND)
    find_package(Parquet CONFIG QUIET)
  endif()
  if(Arrow_FOUND AND Parquet_FOUND)
    message(STATUS "Apache Arrow found: archive writer enabled")
    target_sources(wiretap PRIVATE src/archive_writer.cpp)
    target_compile_definitions(wiretap PUBLIC WIRETAP_HAVE_ARROW=1)
    target_link_libraries(wiretap PUBLIC Arrow::arrow_shared Parquet::parquet_shared)
  else()
    message(WARNING "Apache Arrow/Parquet not found: archive writer disabled "
                    "(install libarrow-dev libparquet-dev, or `brew install apache-arrow`)")
  endif()
endif()

if(WIRETAP_BUILD_TESTS)
  enable_testing()
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  add_subdirectory(tests)
endif()
