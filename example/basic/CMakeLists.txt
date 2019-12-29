if(WIN32)
    set_source_files_properties(example_basic_win.cpp PROPERTIES COMPILE_FLAGS -bigobj)
    add_executable(
        example_basic
        WIN32
        example_basic_win.cpp
    )

    add_custom_command(TARGET example_basic POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.build $<TARGET_FILE_DIR:example_basic>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.media $<TARGET_FILE_DIR:example_basic>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.png $<TARGET_FILE_DIR:example_basic>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/example_basic_thumb.png $<TARGET_FILE_DIR:example_basic>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/upload $<TARGET_FILE_DIR:example_basic>
    )

    if(CMAKE_BUILD_TYPE MATCHES "debug")
        find_file(MSVCP_DLL "msvcp140d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(UCRTBASE_DLL "ucrtbased.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(VCRUNTIME_DLL "vcruntime140d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
        find_file(VCRUNTIME_1_DLL "vcruntime140_1d.dll" PATHS "$ENV{SYSTEMROOT}\\System32")
    else()
        message("TODO - not implemented")
    endif()

    message("Found: ${MSVCP_DLL}, ${UCRTBASE_DLL}, ${VCRUNTIME_DLL}, ${VCRUNTIME_1_DLL}")

    add_custom_command(TARGET example_basic POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:example_basic>/example_basic_dlls"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MSVCP_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${UCRTBASE_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_1_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
    )
endif()