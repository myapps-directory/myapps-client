set(yaml_PREFIX ${CMAKE_BINARY_DIR}/external/yaml)
if(WIN32)
    ExternalProject_Add(
            build-yaml
            EXCLUDE_FROM_ALL 1
            PREFIX ${yaml_PREFIX}
            URL https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.6.3.tar.gz
            CMAKE_ARGS
                -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/external -DYAML_BUILD_SHARED_LIBS=OFF -DYAML_CPP_BUILD_TESTS=OFF
    )

    set(LIBYAML_FOUND TRUE)

    if(CMAKE_BUILD_TYPE MATCHES "debug")
        set(LIBYAML_LIBRARIES libyaml-cppmdd)
    else()
        set(LIBYAML_LIBRARIES libyaml-cppmd)
    endif()

else()
    ExternalProject_Add(
        build-yaml
        EXCLUDE_FROM_ALL 1
        PREFIX ${yaml_PREFIX}
        #URL https://github.com/hyperrealm/libconfig/archive/v1.7.2.tar.gz
        URL https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.6.3.tar.gz
        CMAKE_ARGS
                -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR}/external
    )

    set(LIBYAML_FOUND TRUE)
    set(LIBYAML_LIBRARIES)
endif()