if(WIN32)
    
    set_source_files_properties(updater_win.cpp PROPERTIES COMPILE_FLAGS -bigobj)

    add_executable(updater
        WIN32
        updater_win.cpp
        resource.h
        resource.rc
        ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        updater.build.yml
        updater.png
        updater_thumb.png
        ola_upload
    )
    target_link_libraries(updater comctl32)
    get_property(updater_location TARGET updater PROPERTY RUNTIME_OUTPUT_DIRECTORY)

    message("updater location: ${example_basic_location}")

    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        DEPENDS
        updater.build.yml
        updater.png
        updater_thumb.png
        ola_upload
        COMMENT "Force trigger rebuild when artifact files do change"
    )

    add_custom_command(TARGET updater PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/updater.build.yml $<TARGET_FILE_DIR:updater>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/updater.png $<TARGET_FILE_DIR:updater>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/updater_thumb.png $<TARGET_FILE_DIR:updater>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/ola_upload $<TARGET_FILE_DIR:updater>
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

    add_custom_command(TARGET updater POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:updater>/updater_dlls"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MSVCP_DLL} $<TARGET_FILE_DIR:updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${UCRTBASE_DLL} $<TARGET_FILE_DIR:updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_DLL} $<TARGET_FILE_DIR:updater>/updater_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_1_DLL} $<TARGET_FILE_DIR:updater>/updater_dlls
    )
endif()