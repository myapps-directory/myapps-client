add_executable (ola_client_cli ola_client_cli.cpp)

if(WIN32)
    set_source_files_properties(ola_client_cli.cpp PROPERTIES COMPILE_FLAGS "-bigobj -DOLA_FRONT_URL=\\\"${OLA_FRONT_URL}\\\"")
else()
    set_source_files_properties(ola_client_cli.cpp PROPERTIES COMPILE_FLAGS "-DOLA_FRONT_URL=\\\"${OLA_FRONT_URL}\\\"")
endif()

target_link_libraries (ola_client_cli
    ola_utility
    ola_client_utility
    SolidFrame::solid_frame_mprpc
    SolidFrame::solid_frame_aio_openssl
    SolidFrame::solid_serialization_v3
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${SNAPPY_LIB}
    ${SYSTEM_BASIC_LIBRARIES}
    ${SYSTEM_DYNAMIC_LOAD_LIBRARY}
    ${LIBZIP_LIBRARIES}
    ${LIBREPLXX_LIBRARIES}
    ${LIBYAML_LIBRARIES}
    Threads::Threads
)

set_target_properties(
    ola_client_cli PROPERTIES
        VS_DEBUGGER_WORKING_DIRECTORY $<TARGET_FILE_DIR:ola_client_cli>)

add_dependencies(ola_client_cli build-snappy build-yaml build-libzip build-replxx build-cereal)
install(TARGETS ola_client_cli RUNTIME DESTINATION bin)
install(DIRECTORY $<TARGET_FILE_DIR:ola_client_cli>/certs DESTINATION "bin")

add_custom_command(TARGET ola_client_cli POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/certs  $<TARGET_FILE_DIR:ola_client_cli>/certs
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_SSL_DLL} $<TARGET_FILE_DIR:ola_client_auth>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_CRYPTO_DLL} $<TARGET_FILE_DIR:ola_client_auth>
)
