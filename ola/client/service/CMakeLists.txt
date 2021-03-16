message("FUSE_INCLUDE_DIRECTORY = ${FUSE_INCLUDE_DIRECTORY}")

add_subdirectory(test)

if(WIN32)
    include_directories("${FUSE_INCLUDE_DIRECTORY}")
    add_executable(ola_client_service WIN32
        ola_client_service.cpp engine.hpp engine.cpp file_cache.hpp file_cache.cpp
        shortcut_creator.hpp shortcut_creator.cpp
    )

    set_source_files_properties(engine.cpp PROPERTIES COMPILE_FLAGS -bigobj)
    set_source_files_properties(ola_client_service.cpp PROPERTIES COMPILE_FLAGS "-DOLA_FRONT_URL=\\\"${OLA_FRONT_URL}\\\"")

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(ola_client_service PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(ola_client_service PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(ola_client_service
        ${FUSE_LIBRARY}
        ola_utility
        ola_client_utility
        SolidFrame::solid_frame_mprpc
        SolidFrame::solid_frame_aio_openssl
        SolidFrame::solid_serialization_v3
        ${SNAPPY_LIB}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
    )

    set_target_properties(
        ola_client_service PROPERTIES
        VS_DEBUGGER_WORKING_DIRECTORY $<TARGET_FILE_DIR:ola_client_service>)

    add_custom_command(TARGET ola_client_service POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/ola/client/utility/certs  $<TARGET_FILE_DIR:ola_client_service>/certs
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_SSL_DLL} $<TARGET_FILE_DIR:ola_client_auth>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_CRYPTO_DLL} $<TARGET_FILE_DIR:ola_client_auth>
    )

    install(TARGETS ola_client_service RUNTIME DESTINATION bin)
    set_property(INSTALL "bin/$<TARGET_FILE_NAME:ola_client_service>"
        PROPERTY CPACK_STARTUP_SHORTCUTS "ola_client_service"
    )

    add_executable(passthrough passthrough.cpp)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(passthrough PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(passthrough PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(passthrough
        ${FUSE_LIBRARY}
		ola_utility
        SolidFrame::solid_frame_mprpc
        SolidFrame::solid_frame_aio_openssl
        SolidFrame::solid_serialization_v2
        ${SNAPPY_LIB}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
    )

    add_executable(passthrough_c passthrough_c.cpp)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(passthrough_c PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(passthrough_c PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(passthrough_c
        ${FUSE_LIBRARY}
		ola_utility
        SolidFrame::solid_frame_mprpc
        SolidFrame::solid_frame_aio_openssl
        SolidFrame::solid_serialization_v2
        ${SNAPPY_LIB}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
    )

    add_executable(test_security test_security.cpp)
endif(WIN32)
