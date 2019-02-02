set(config_PREFIX ${CMAKE_BINARY_DIR}/external/config)
if(WIN32)
    ExternalProject_Add(
            build-config
            EXCLUDE_FROM_ALL 1
            PREFIX ${config_PREFIX}
            URL https://github.com/hyperrealm/libconfig/archive/v1.7.2.tar.gz
            CMAKE_ARGS
                -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/external -DBUILD_SHARED_LIBS=false -DBUILD_EXAMPLES=true -DBUILD_TESTS=false
    )

    set(LIBCONFIG_FOUND TRUE)
    set(LIBCONFIG_LIBRARIES libconfig++ Shlwapi)

else()
    ExternalProject_Add(
        build-config
        EXCLUDE_FROM_ALL 1
        PREFIX ${config_PREFIX}
        #URL https://github.com/hyperrealm/libconfig/archive/v1.7.2.tar.gz
        URL https://hyperrealm.github.io/libconfig/dist/libconfig-1.7.2.tar.gz
        DOWNLOAD_NO_PROGRESS ON
        CONFIGURE_COMMAND ./configure --disable-examples --disable-shared --prefix ${CMAKE_BINARY_DIR}/external
        BUILD_COMMAND make
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE 1
        LOG_UPDATE ON
        LOG_CONFIGURE ON
        LOG_BUILD ON
        LOG_INSTALL ON
    )

    set(LIBCONFIG_FOUND TRUE)
    set(LIBCONFIG_LIBRARIES config++)
endif()
