cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
cmake_policy(SET CMP0091 NEW)
cmake_policy(SET CMP0115 NEW)
cmake_policy(SET CMP0135 NEW)

project(MyAppsClient VERSION 0.18)

set(EXTERNAL_DIR "" CACHE PATH "External dependencies folder")

#set(CMAKE_SUPPRESS_REGENERATION OFF CACHE BOOLEAN "Suppress Regeneration")

execute_process(
    COMMAND "git" "rev-parse" "HEAD"
    WORKING_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_VERSION ${VERSION}
    OUTPUT_STRIP_TRAILING_WHITESPACE)

set(PROJECT_VERSION_PATCH "${GIT_VERSION}")

message("project version: ${PROJECT_VERSION} - ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Setting build type to 'release' as none was specified.")
    set(CMAKE_BUILD_TYPE "release" CACHE STRING "Choose the type of build." FORCE)
    # Set the possible values of build type for cmake-gui
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "release" "debug" "maintain")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)

if(CMAKE_BUILD_TYPE STREQUAL "release")
    #force a single configuration type on Windows builds
    set(CMAKE_CONFIGURATION_TYPES "release")
    set(CONFIGURATION_TYPE "release")
endif(CMAKE_BUILD_TYPE STREQUAL "release")

if(CMAKE_BUILD_TYPE STREQUAL "maintain")
    set(CMAKE_VERBOSE_MAKEFILE ON)

    #force a single configuration type on Windows builds
    set(CMAKE_CONFIGURATION_TYPES "RelWithDebInfo")
    set(CONFIGURATION_TYPE "RelWithDebInfo")
endif(CMAKE_BUILD_TYPE STREQUAL "maintain")


if(CMAKE_BUILD_TYPE STREQUAL "debug")
    set(CMAKE_VERBOSE_MAKEFILE ON)
    #force a single configuration type on Windows builds
    set(CMAKE_CONFIGURATION_TYPES "debug")
    set(CONFIGURATION_TYPE "debug")
endif(CMAKE_BUILD_TYPE STREQUAL "debug")

set(QTPREFIX_DIR "" CACHE PATH "QT Prefix directory")

message("project build type: ${CMAKE_BUILD_TYPE}")

set(MYAPPS_FRONT_URL "front.myapps.directory:443" CACHE STRING "MyApps.directory Front Default URL")
set(EXTRA_DEFINITIONS "${EXTRA_DEFINITIONS}" CACHE STRING "Extra compiler definitions")
add_definitions(${EXTRA_DEFINITIONS})

###############################################################################
# Build configuration
###############################################################################
set(MYAPPS_CLIENT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(MYAPPS_CLIENT_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(MYAPPS_CLIENT_VERSION_PATCH ${PROJECT_VERSION_PATCH})

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

include(cmake/build-lz4.cmake)

include(cmake/build-yaml.cmake)

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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.hpp.in ${CMAKE_BINARY_DIR}/myapps/client/client_config.hpp)

###############################################################################

###############################################################################
# C++ Standard
###############################################################################

set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)

###############################################################################
# Static Analisys
###############################################################################

include(cmake/source-analisys.cmake)

###############################################################################
# ctest support
enable_testing()
include(CTest)
###############################################################################

set(CPACK_PACKAGE_NAME                  "MyApps.directory")
set(CPACK_PACKAGE_VERSION               "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_FILE_NAME             "${CPACK_PACKAGE_NAME}-${CMAKE_BUILD_TYPE}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")

add_subdirectory(myapps)
add_subdirectory(example)
add_subdirectory(cpack/wix)
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

install (FILES ${CMAKE_CURRENT_SOURCE_DIR}/cpack/readme.txt DESTINATION "/")

message(STATUS "Generating ${CPACK_GENERATOR}  package")

string(TIMESTAMP YMDHM "%y%m%d%H%M")
#string(TIMESTAMP YEAR "%Y")

set(CPACK_PACKAGE_VENDOR                "MyApps.directory")
set(CPACK_PACKAGE_VERSION_MAJOR         "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR         "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGING_INSTALL_PREFIX      ${CMAKE_CURRENT_BINARY_DIR})
set(CPACK_RELEASE_VER                   ${YMDHM})
set(CPACK_PACKAGE_EXECUTABLES           "myapps_cli" "MyApps.directory CLI" "myapps_auth" "MyApps.directory Login" "myapps_service_filesystem" "MyApps.directory Applications Virtual FileSystem Service")
set(CPACK_PACKAGE_CONTACT               "office@myapps.directory")
set(CPACK_PACKAGING_INSTALL_PREFIX      ${PACKAGING_INSTALL_PREFIX})
SET(CPACK_PACKAGE_INSTALL_DIRECTORY     "MyApps.dir")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY   "MyApps.dir - Applications Virtual FileSystem Service")

set(CPACK_WIX_TEMPLATE                  "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/myapps.wxs")
#set(CPACK_WIX_PRODUCT_GUID              "80D72FCC-5083-406C-B592-BE442CEA4708")
SET(CPACK_WIX_UPGRADE_GUID              "5C004871-28A4-43D5-947E-10F080CED048")
SET(CPACK_WIX_LICENSE_RTF               "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/license.rtf")
SET(CPACK_WIX_PRODUCT_ICON              "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/app.ico")
SET(CPACK_WIX_UI_BANNER                 "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/banner_sml.bmp")
SET(CPACK_WIX_UI_DIALOG                 "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/banner_big.bmp")
set(CPACK_WIX_PATCH_FILE                "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/service.patch")
set(CPACK_WIX_EXTENSIONS                WixUIExtension WixUtilExtension WixBalExtension)
set(CPACK_WIX_EXTRA_FLAGS sw)
set(CPACK_WIX_PROPERTY_ARPURLINFOABOUT "https://myapps.directory")
set(CPACK_WIX_PROPERTY_ARPCONTACT       ${CPACK_PACKAGE_CONTACT})
set(CPACK_WIX_PROPERTY_ARPCOMMENTS      "CMake is a cross-platform, open-source build system.")
set(CPACK_WIX_EXTRA_SOURCES             "${CMAKE_BINARY_DIR}/cpack/wix/custom_action_dll.wxs")



if(WIN32)
    set(WIX_BUNDLE_ICON "${CMAKE_SOURCE_DIR}/myapps/client/auth/auth.ico")
    set(WIX_BUNDLE_WINFSP_MSI src/winfsp-2.0.23075.msi)
    set(WIX_BUNDLE_WINFSP_URL https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi)

    ExternalProject_Add(
        WinFSP_Download
        PREFIX "${CMAKE_BINARY_DIR}"
        URL ${WIX_BUNDLE_WINFSP_URL}
        DOWNLOAD_NO_EXTRACT true
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
    )

    file(TO_CMAKE_PATH "$ENV{WIX}" CPACK_WIX_ROOT)
    find_program(WIX_TOOL_CANDLE NAMES candle.exe PATHS  ${CPACK_WIX_ROOT}/bin)
    find_program(WIX_TOOL_LIGHT NAMES light.exe PATHS  ${CPACK_WIX_ROOT}/bin)
    if(NOT WIX_TOOL_CANDLE AND NOT WIX_TOOL_LIGHT)
        message(STATUS "CMake_RUN_CLANG_TIDY is ON but clang-tidy is not found!")
    else()
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/bundle.wxs.in ${CMAKE_BINARY_DIR}/bundle.wxs) 

        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Bundle-${CPACK_PACKAGE_FILE_NAME}.exe
            COMMAND ${WIX_TOOL_CANDLE} ${CMAKE_CURRENT_BINARY_DIR}/bundle.wxs -ext WixBalExtension
            COMMAND ${WIX_TOOL_LIGHT} ${CMAKE_CURRENT_BINARY_DIR}/bundle.wixobj -ext WixBalExtension -out "Bundle-${CPACK_PACKAGE_FILE_NAME}.exe"
            DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/bundle.wxs
        )

        add_custom_target(BUNDLE
            DEPENDS
            ${CMAKE_CURRENT_BINARY_DIR}/Bundle-${CPACK_PACKAGE_FILE_NAME}.exe
        )
        add_dependencies(BUNDLE WinFSP_Download)
    endif()

    
endif()

#set(CPACK_WIX_EXTRA_SOURCES             "${CMAKE_CURRENT_SOURCE_DIR}/cpack/wix/myapps_dirs.wxs")
#set(CPACK_WIX_SKIP_PROGRAM_FOLDER       TRUE)
#set(CPACK_WIX_PROGRAM_MENU_FOLDER       "")
if(CMAKE_BUILD_TYPE MATCHES "debug")
    if (MSVC)
        #string(REGEX REPLACE "Visual Studio ([0-9]+).*" "\\1" MSVC_VERSION "${CMAKE_GENERATOR}")
        set(MYAPPS_MSVC_VERSION 140)
        # Starting with Visual Studio 2015 (MSVC_VERSION==14) the msvcr dll has been renamed to vcruntime.
        find_file(MYAPPS_VCRUNTIME_DLL "vcruntime${MYAPPS_MSVC_VERSION}_1.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        install(FILES  ${MYAPPS_VCRUNTIME_DLL} DESTINATION "bin")
        find_file(MYAPPS_VCRUNTIMED_DLL "vcruntime${MYAPPS_MSVC_VERSION}_1d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        install(FILES  ${MYAPPS_VCRUNTIMED_DLL} DESTINATION "bin")
        find_file(MYAPPS_VCP_DLL "msvcp${MYAPPS_MSVC_VERSION}_1d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        install(FILES  ${MYAPPS_VCP_DLL} DESTINATION "bin")
    endif()
endif()

set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION "bin")
set(CMAKE_INSTALL_UCRT_LIBRARIES TRUE)
set(CMAKE_INSTALL_DEBUG_LIBRARIES TRUE)

include(InstallRequiredSystemLibraries)

include(CPack)


