if(WIN32)
    
    set_source_files_properties(updater_win.cpp PROPERTIES COMPILE_FLAGS -bigobj)

    add_executable(myapps_updater
        WIN32
        updater_win.cpp
        resource.h
        resource.rc
        ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        updater.build.yml.in
        updater.png
        updater_thumb.png
        upload.in
    )

    target_link_libraries(myapps_updater
        myapps_utility
        myapps_client_utility
    )

    add_dependencies(myapps_updater myapps_cli)

    get_property(updater_location TARGET myapps_updater PROPERTY RUNTIME_OUTPUT_DIRECTORY)

    message("updater location: ${example_basic_location}")

    set(MYAPPS_INSTALLER_NAME "${CPACK_PACKAGE_FILE_NAME}.msi")

    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        DEPENDS
        updater.build.yml.in
        updater.png
        updater_thumb.png
        upload.in
        ${MYAPPS_INSTALLER_NAME}
        COMMENT "Force trigger rebuild when artifact files do change"
    )

    if(CMAKE_BUILD_TYPE MATCHES "debug")
        find_file(MSVCP_DLL "msvcp140d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(UCRTBASE_DLL "ucrtbased.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(VCRUNTIME_DLL "vcruntime140d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(VCRUNTIME_1_DLL "vcruntime140_1d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
    else()
        find_file(MSVCP_DLL "msvcp140.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(UCRTBASE_DLL "ucrtbase.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(VCRUNTIME_DLL "vcruntime140.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(VCRUNTIME_1_DLL "vcruntime140_1.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
    endif()

    message("Found: ${MSVCP_DLL}, ${UCRTBASE_DLL}, ${VCRUNTIME_DLL}, ${VCRUNTIME_1_DLL}")

    add_custom_command(TARGET myapps_updater POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:myapps_updater>/updater_dlls"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MSVCP_DLL} $<TARGET_FILE_DIR:myapps_updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${UCRTBASE_DLL} $<TARGET_FILE_DIR:myapps_updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_DLL} $<TARGET_FILE_DIR:myapps_updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_1_DLL} $<TARGET_FILE_DIR:myapps_updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_CRYPTO_DLL} $<TARGET_FILE_DIR:myapps_updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/updater.build.yml.in" $<TARGET_FILE_DIR:myapps_updater>/updater.build.yml
        #COMMAND ${CMAKE_COMMAND} -DINFILE="${CMAKE_CURRENT_SOURCE_DIR}/updater.build.yml.in"  -DOUTFILE=$<TARGET_FILE_DIR:myapps_updater>/updater.build.yml -P "${CMAKE_SOURCE_DIR}/cmake/generic-configure-file.cmake"
        COMMAND ${CMAKE_COMMAND} -DINFILE="${CMAKE_CURRENT_SOURCE_DIR}/upload.in"  -DOUTFILE=$<TARGET_FILE_DIR:myapps_updater>/upload_updater -DPROJECT_ROOT_DIR="${CMAKE_SOURCE_DIR}" -DMYAPPS_INSTALLER_PATH="${CMAKE_BINARY_DIR}" -DMYAPPS_INSTALLER_NAME="${MYAPPS_INSTALLER_NAME}" -P "${CMAKE_SOURCE_DIR}/cmake/generic-configure-file.cmake"
    )
endif()