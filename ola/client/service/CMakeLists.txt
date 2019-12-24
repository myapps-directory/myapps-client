message("FUSE_INCLUDE_DIRECTORY = ${FUSE_INCLUDE_DIRECTORY}")

add_subdirectory(test)

if(WIN32)
    include_directories("${FUSE_INCLUDE_DIRECTORY}")
    add_executable(ola_client_service WIN32
        ola_client_service.cpp engine.hpp engine.cpp file_cache.hpp file_cache.cpp
        shortcut_creator.hpp shortcut_creator.cpp
    )

    set_source_files_properties(engine.cpp PROPERTIES COMPILE_FLAGS -bigobj)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(ola_client_service PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(ola_client_service PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(ola_client_service
        ${FUSE_LIBRARY}
        ola_utility
        solid_frame_mprpc
        solid_frame_aio_openssl
        solid_serialization_v2
        ${OPENSSL_LIBRARIES}
		${SNAPPY_LIB}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
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
        solid_frame_mprpc
        solid_frame_aio_openssl
        solid_serialization_v2
        ${OPENSSL_LIBRARIES}
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
        solid_frame_mprpc
        solid_frame_aio_openssl
        solid_serialization_v2
        ${OPENSSL_LIBRARIES}
		${SNAPPY_LIB}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
    )

    add_executable(test_security test_security.cpp)
endif(WIN32)
