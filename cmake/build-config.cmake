set(config_PREFIX ${CMAKE_BINARY_DIR}/external/config)

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
set(LIBCONFIG_LIBRARIES config config++)
