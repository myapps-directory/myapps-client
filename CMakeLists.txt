cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

project(OlaClient VERSION 1.0)

set(EXTERNAL_DIR "" CACHE PATH "External dependencies folder")

execute_process(
    COMMAND "git" "rev-parse" "HEAD"
    WORKING_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_VERSION ${VERSION}
    OUTPUT_STRIP_TRAILING_WHITESPACE)

set(PROJECT_VERSION_PATCH "${GIT_VERSION}")

message("project version: ${PROJECT_VERSION} - ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (CMAKE_CXX_STANDARD 14)

set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS}" CACHE STRING "Extra compiler definitions")
add_definitions(${EXTRA_DEFINITIONS})

###############################################################################
# Build configuration
###############################################################################
set(OLA_CLIENT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(OLA_CLIENT_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(OLA_CLIENT_VERSION_PATCH ${PROJECT_VERSION_PATCH})

###############################################################################
# Build external projects
###############################################################################

include(ExternalProject)

###############################################################################

if(EXTERNAL_DIR STREQUAL "")
    message(FATAL_ERROR "EXTERNAL DIR not specified.")
endif()


include(cmake/find-boost.cmake)

include(cmake/find-openssl.cmake)

include(cmake/find-solidframe.cmake)

include(cmake/build-cereal.cmake)

include(cmake/build-snappy.cmake)

include(cmake/build-config.cmake)

include(cmake/build-libzip.cmake)

set(SYSTEM_BASIC_LIBRARIES pthread rt)
    
find_library(ATOMIC_LIBRARY NAMES atomic atomic.so.1 libatomic.so.1)

if(ATOMIC_LIBRARY)
    message("Atomic library found: ${ATOMIC_LIBRARY}")
    list(APPEND SYSTEM_BASIC_LIBRARIES atomic)
endif()

set(SYSTEM_DYNAMIC_LOAD_LIBRARY dl)

###############################################################################
include_directories(
    "${EXTERNAL_DIR}/include/"
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_BINARY_DIR}"
    "${CMAKE_BINARY_DIR}/external/include"
)

link_directories(
    "${CMAKE_BINARY_DIR}/external"
    "${CMAKE_BINARY_DIR}"
    "${EXTERNAL_DIR}/lib"
    "${CMAKE_BINARY_DIR}/external/lib"
)

###############################################################################
# OS Configuration
###############################################################################


###############################################################################
# cmake_config.hpp support
include(cmake/check.config.cmake)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.hpp.in ${CMAKE_BINARY_DIR}/ola/client/client_config.hpp)

###############################################################################

###############################################################################
# C++ Standard
###############################################################################

set (CMAKE_CXX_STANDARD 14)

###############################################################################
# Static Analisys
###############################################################################

include(cmake/source-analisys.cmake)

###############################################################################
# ctest support
enable_testing()
include(CTest)
###############################################################################
add_subdirectory(ola)

###############################################################################
include(cmake/source-format.cmake)
###############################################################################

###############################################################################
# CPack
###############################################################################

