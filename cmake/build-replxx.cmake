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
    set(LIBREPLXX_LIBRARIES libreplxx)
else()
    set(LIBREPLXX_LIBRARIES replxx)
endif()
