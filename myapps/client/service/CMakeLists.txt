message("FUSE_INCLUDE_DIRECTORY = ${FUSE_INCLUDE_DIRECTORY}")

add_subdirectory(test)

if(WIN32)
    include_directories("${FUSE_INCLUDE_DIRECTORY}")
    add_executable(myapps_service_filesystem WIN32
        filesystem_service.cpp engine.hpp engine.cpp file_cache.hpp file_cache.cpp
        file_data.hpp file_data.cpp
        shortcut_creator.hpp shortcut_creator.cpp
    )

    set_source_files_properties(engine.cpp PROPERTIES COMPILE_FLAGS -bigobj)
    set_source_files_properties(filesystem_service.cpp PROPERTIES COMPILE_FLAGS "-DOLA_FRONT_URL=\\\"${OLA_FRONT_URL}\\\"")

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(myapps_service_filesystem PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(myapps_service_filesystem PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(myapps_service_filesystem
        ${FUSE_LIBRARY}
        myapps_utility
        myapps_client_utility
        SolidFrame::solid_frame_mprpc
        SolidFrame::solid_frame_aio_openssl
        SolidFrame::solid_serialization_v3
        ${SNAPPY_LIB}
        ${LZ4_LIB}
        Boost::program_options
        Boost::system
        Boost::filesystem
    )

    add_dependencies(myapps_service_filesystem build-snappy build-lz4)

    set_target_properties(
        myapps_service_filesystem PROPERTIES
        VS_DEBUGGER_WORKING_DIRECTORY $<TARGET_FILE_DIR:myapps_service_filesystem>)

    add_custom_command(TARGET myapps_service_filesystem POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/myapps/client/utility/certs  $<TARGET_FILE_DIR:myapps_service_filesystem>/certs
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_SSL_DLL} $<TARGET_FILE_DIR:myapps_auth>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_CRYPTO_DLL} $<TARGET_FILE_DIR:myapps_auth>
    )

    install(TARGETS myapps_service_filesystem RUNTIME DESTINATION bin)
    set_property(INSTALL "bin/$<TARGET_FILE_NAME:myapps_service_filesystem>"
        PROPERTY CPACK_STARTUP_SHORTCUTS "myapps_service_filesystem"
    )

    add_executable(passthrough passthrough.cpp)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(passthrough PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(passthrough PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(passthrough
        ${FUSE_LIBRARY}
		myapps_utility
        SolidFrame::solid_frame_mprpc
        SolidFrame::solid_frame_aio_openssl
        ${SNAPPY_LIB}
        Boost::program_options
        Boost::system
        Boost::filesystem
    )

    add_executable(passthrough_c passthrough.c)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(passthrough_c PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(passthrough_c PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(passthrough_c
        ${FUSE_LIBRARY}
		myapps_utility
        SolidFrame::solid_frame_mprpc
        SolidFrame::solid_frame_aio_openssl
        ${SNAPPY_LIB}
        Boost::program_options
        Boost::system
        Boost::filesystem
    )

    add_executable(test_security test_security.cpp)
endif(WIN32)
