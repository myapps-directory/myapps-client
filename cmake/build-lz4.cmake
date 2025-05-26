set(lz4_PREFIX ${CMAKE_BINARY_DIR}/external/lz4)

ExternalProject_Add(
    build-lz4
    EXCLUDE_FROM_ALL 1
    PREFIX ${lz4_PREFIX}
    URL https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz
    DOWNLOAD_NO_PROGRESS ON
    SOURCE_SUBDIR build/cmake/
    CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/external -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DLZ4_BUILD_CLI=OFF -DLZ4_BUILD_LEGACY_LZ4C=OFF
            
    #BUILD_COMMAND ${CMAKE_COMMAND} --build . --config ${CONFIGURATION_TYPE}
    #INSTALL_COMMAND ${CMAKE_COMMAND} --build . --config ${CONFIGURATION_TYPE} --target install
    LOG_UPDATE ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
)

if(WIN32)
    set(LZ4_LIB ${CMAKE_BINARY_DIR}/external/lib/lz4.lib)
else()
    set(LZ4_LIB ${CMAKE_BINARY_DIR}/external/lib/liblz4.a)
endif()
