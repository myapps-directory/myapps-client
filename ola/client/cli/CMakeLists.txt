add_executable (ola_client_cli ola_client_cli.cpp ../../common/ola_front_protocol.hpp)

if(WIN32)
    set_source_files_properties(ola_client_cli.cpp PROPERTIES COMPILE_FLAGS -bigobj)
endif()

target_link_libraries (ola_client_cli
    ola_utility
    solid_frame_mprpc
    solid_frame_aio_openssl
    solid_serialization_v2
    ${OPENSSL_LIBRARIES}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${SNAPPY_LIB}
    ${SYSTEM_BASIC_LIBRARIES}
    ${SYSTEM_DYNAMIC_LOAD_LIBRARY}
    ${LIBCONFIG_LIBRARIES}
    ${LIBZIP_LIBRARIES}
    ${LIBREPLXX_LIBRARIES}
    Threads::Threads
)

add_dependencies(ola_client_cli build-snappy build-config build-libzip build-replxx build-cereal)
install(TARGETS ola_client_cli RUNTIME DESTINATION bin)
