add_executable (myapps_cli client_cli.cpp)

if(WIN32)
    set_source_files_properties(client_cli.cpp PROPERTIES COMPILE_FLAGS "-bigobj -DMYAPPS_FRONT_URL=\\\"${MYAPPS_FRONT_URL}\\\"")
else()
    set_source_files_properties(client_cli.cpp PROPERTIES COMPILE_FLAGS "-DMYAPPS_FRONT_URL=\\\"${MYAPPS_FRONT_URL}\\\"")
endif()

target_link_libraries (myapps_cli
    myapps_utility
    myapps_client_utility
    SolidFrame::solid_frame_mprpc
    SolidFrame::solid_frame_aio_openssl
    SolidFrame::solid_serialization_v3
    Boost::program_options
    Boost::system
    Boost::filesystem
    ${SNAPPY_LIB}
    ${LZ4_LIB}
    ${SYSTEM_BASIC_LIBRARIES}
    ${SYSTEM_DYNAMIC_LOAD_LIBRARY}
    ${LIBREPLXX_LIBRARIES}
    yaml-cpp::yaml-cpp
    Threads::Threads
)

set_target_properties(
    myapps_cli PROPERTIES
        VS_DEBUGGER_WORKING_DIRECTORY $<TARGET_FILE_DIR:myapps_cli>)

add_dependencies(myapps_cli build-snappy build-lz4 yaml-cpp build-replxx build-cereal)

install(TARGETS myapps_cli RUNTIME DESTINATION bin)
install(DIRECTORY $<TARGET_FILE_DIR:myapps_cli>/certs DESTINATION "bin")

add_custom_command(TARGET myapps_cli POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/myapps/client/utility/certs  $<TARGET_FILE_DIR:myapps_cli>/certs
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_SSL_DLL} $<TARGET_FILE_DIR:myapps_cli>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_CRYPTO_DLL} $<TARGET_FILE_DIR:myapps_cli>
)
