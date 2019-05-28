message("FUSE_INCLUDE_DIRECTORY = ${FUSE_INCLUDE_DIRECTORY}")

if(WIN32)
    include_directories("${FUSE_INCLUDE_DIRECTORY}")
    add_executable(ola_client_service WIN32 ola_client_service.cpp engine.hpp engine.cpp filecache.hpp filecache.cpp)

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

    add_executable(test_security test_security.cpp)
endif(WIN32)
