set(libzip_PREFIX ${CMAKE_BINARY_DIR}/external/libzip)
set(zlib_PREFIX ${CMAKE_BINARY_DIR}/external/zlib)

ExternalProject_Add(
        build-zlib
        EXCLUDE_FROM_ALL 1
        PREFIX ${zlib_PREFIX}
        URL https://zlib.net/zlib-1.2.11.tar.gz
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/external
)
        
ExternalProject_Add(
    build-libzip
    DEPENDS build-zlib
    EXCLUDE_FROM_ALL 1
    PREFIX ${libzip_PREFIX}
    URL https://libzip.org/download/libzip-1.5.1.tar.gz
    DOWNLOAD_NO_PROGRESS ON
    CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/external -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_BUILD_TYPE=${CONFIGURATION_TYPE} -DOPENSSL_ROOT_DIR=${EXTERNAL_DIR} -DBUILD_SHARED_LIBS:BOOL=false -DBUILD_TOOLS=OFF -DBUILD_REGRESS=OFF  -DBUILD_EXAMPLES=OFF -DBUILD_DOC=OFF
    BUILD_COMMAND ${CMAKE_COMMAND} --build . --config ${CONFIGURATION_TYPE}
    INSTALL_COMMAND ${CMAKE_COMMAND} --build . --config ${CONFIGURATION_TYPE} --target install
    LOG_UPDATE ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
)
if(WIN32)
    set(LIBZIP_FOUND TRUE)
    if(CMAKE_BUILD_TYPE MATCHES "debug")
        set(LIBZIP_LIBRARIES zip zlibstaticd)
    else()
        set(LIBZIP_LIBRARIES zip zlibstatic)
    endif()
    message("Configuration type: ${CMAKE_BUILD_TYPE} zip libraries: ${LIBZIP_LIBRARIES}")
else()
    set(LIBZIP_FOUND TRUE)
    set(LIBZIP_LIBRARIES zip z)
endif(WIN32)
