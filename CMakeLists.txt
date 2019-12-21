cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

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

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "release")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)

set(QT5PREFIX_DIR "" CACHE PATH "QT Prefix directory")
set(CMAKE_CONFIGURATION_TYPES "release" CACHE STRING "" FORCE)
set(CONFIGURATION_TYPE "release")

message("project build type: ${CMAKE_BUILD_TYPE}")

if(CMAKE_BUILD_TYPE STREQUAL "debug")
    #force a single configuration type on Windows builds
    set(CMAKE_CONFIGURATION_TYPES "debug" CACHE STRING "" FORCE)
    set(CONFIGURATION_TYPE "debug")
else()
    #force a single configuration type on Windows builds
    set(CMAKE_CONFIGURATION_TYPES "release" CACHE STRING "" FORCE)
    set(CONFIGURATION_TYPE "release")
endif()

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

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(Threads REQUIRED)

include(cmake/find-boost.cmake)

include(cmake/find-openssl.cmake)

include(cmake/find-solidframe.cmake)

include(cmake/find-fuse.cmake)

include(cmake/build-cereal.cmake)

include(cmake/build-snappy.cmake)

include(cmake/build-config.cmake)

include(cmake/build-libzip.cmake)

include(cmake/build-replxx.cmake)

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

if(LINUX)
    set(SYSTEM_BASIC_LIBRARIES rt)
    find_library(ATOMIC_LIBRARY NAMES atomic atomic.so.1 libatomic.so.1)

    if(ATOMIC_LIBRARY)
        message("Atomic library found: ${ATOMIC_LIBRARY}")
        list(APPEND SYSTEM_BASIC_LIBRARIES atomic)
    endif()

    set(SYSTEM_DYNAMIC_LOAD_LIBRARY dl)
elseif(WIN32)
    set(SYSTEM_BASIC_LIBRARIES CRYPT32 Ws2_32)
else()
endif()

###############################################################################
include_directories(
    "${EXTERNAL_DIR}/include"
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

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )

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

set (CMAKE_CXX_STANDARD 17)

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
add_subdirectory(example)

###############################################################################
include(cmake/source-format.cmake)
###############################################################################

###############################################################################
# CPack
###############################################################################
if(WIN32)
    set(CPACK_GENERATOR "WIX")
    set(PACKAGING_INSTALL_PREFIX "")
else()
endif()

message(STATUS "Generating ${CPACK_GENERATOR}  package")
    
string(TIMESTAMP OLA_YMDHM "%y%m%d%H%M")
string(TIMESTAMP OLA_YEAR "%Y")

set(CPACK_PACKAGE_VENDOR                "AphorSoft SRL")
set(CPACK_PACKAGE_VERSION               "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_MAJOR         "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR         "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGING_INSTALL_PREFIX      ${CMAKE_CURRENT_BINARY_DIR})
set(CPACK_RELEASE_VER                   ${OLA_YMDHM})
set(CPACK_PACKAGE_NAME                  "ola")
set(CPACK_PACKAGE_EXECUTABLES           "ola_client_cli" "OLA CLI" "ola_client_auth" "OLA Client Authenticator GUI" "ola_client_service" "OLA Client Service")
set(CPACK_PACKAGE_FILE_NAME             "${CPACK_PACKAGE_NAME}-${CMAKE_BUILD_TYPE}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_CONTACT               "office@aphorsoft.com")
set(CPACK_PACKAGING_INSTALL_PREFIX      ${PACKAGING_INSTALL_PREFIX})
SET(CPACK_PACKAGE_INSTALL_DIRECTORY     "OLA")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY   "OLA - On Line Application Service")


set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS       ON)
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION    "OLA - On Line Application Service")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA  "${CMAKE_CURRENT_SOURCE_DIR}/cpack/deb/postinst;${CMAKE_CURRENT_SOURCE_DIR}/cpack/deb/prerm;${CMAKE_CURRENT_SOURCE_DIR}/cpack/deb/postrm")

#set(CPACK_WIX_TEMPLATE                  "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/template.in")
SET(CPACK_WIX_UPGRADE_GUID              "624AF6DA-4B24-4D57-A2E5-45371EE6DBB5")
SET(CPACK_WIX_LICENSE_RTF               "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/license.rtf")
SET(CPACK_WIX_PRODUCT_ICON              "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/app.ico")
SET(CPACK_WIX_UI_BANNER                 "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/banner_sml.bmp")
SET(CPACK_WIX_UI_DIALOG                 "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/banner_big.bmp")
set(CPACK_WIX_PATCH_FILE                "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/service.patch")
set(CPACK_WIX_EXTENSIONS                "WixUtilExtension")

set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION "bin")
set(CMAKE_INSTALL_UCRT_LIBRARIES TRUE)

include(InstallRequiredSystemLibraries)

include(CPack)