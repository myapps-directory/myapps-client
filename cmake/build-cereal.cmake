set(cereal_PREFIX ${CMAKE_BINARY_DIR}/external/cereal)

ExternalProject_Add(
    build-cereal
    PREFIX ${cereal_PREFIX}
    URL "https://github.com/USCiLab/cereal/archive/v1.2.2.tar.gz"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory "${cereal_PREFIX}/src/build-cereal/include/cereal" "${CMAKE_BINARY_DIR}/external/include/cereal"
    INSTALL_COMMAND ""
)
