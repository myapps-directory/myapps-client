message("FUSE_INCLUDE_DIRECTORY = ${FUSE_INCLUDE_DIRECTORY}")

if(WIN32)
    include_directories("${FUSE_INCLUDE_DIRECTORY}")
    add_executable(ola_client_service ola_client_service.cpp)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(ola_client_service PRIVATE /DELAYLOAD:winfsp-x64.dll)
    else()
        target_link_options(ola_client_service PRIVATE /DELAYLOAD:winfsp-x86.dll)
    endif()

    target_link_libraries(ola_client_service
        ${FUSE_LIBRARY}
    )
endif(WIN32)
