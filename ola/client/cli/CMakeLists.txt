add_executable (ola_client_cli ola_client_cli.cpp ../../common/ola_front_protocol.hpp)

target_link_libraries (ola_client_cli
    ola_utility
    solid_frame_mprpc
    solid_frame_aio_openssl
    solid_serialization_v2
    ${OPENSSL_LIBRARIES}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${SNAPPY_LIB}
    ${SYSTEM_BASIC_LIBRARIES}
    ${SYSTEM_DYNAMIC_LOAD_LIBRARY}
    ${LIBCONFIG_LIBRARIES}
)

add_dependencies(ola_client_cli build-snappy build-config)

