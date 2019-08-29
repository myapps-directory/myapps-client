set(replxx_PREFIX ${CMAKE_BINARY_DIR}/external/replxx)

ExternalProject_Add(
        build-replxx
        EXCLUDE_FROM_ALL 1
        PREFIX ${replxx_PREFIX}
        URL https://github.com/AmokHuginnsson/replxx/archive/release-0.0.1.tar.gz
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/external -DREPLXX_BuildExamples:BOOLEAN=OFF
)

set(LIBREPLXX_FOUND TRUE)

if(WIN32)
    if(CMAKE_BUILD_TYPE MATCHES "debug")
        set(LIBREPLXX_LIBRARIES replxx-d)
    else()
        set(LIBREPLXX_LIBRARIES replxx)
    endif()
else()
    set(LIBREPLXX_LIBRARIES replxx)
endif()
