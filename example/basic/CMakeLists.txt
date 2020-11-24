if(WIN32)
    
    set_source_files_properties(example_basic_win.cpp PROPERTIES COMPILE_FLAGS -bigobj)

    add_executable(
        example_basic
        WIN32
        example_basic_win.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        example_basic.build.yml
        example_basic.png
        example_basic_thumb.png
        ola_upload
    )

    get_property(example_basic_location TARGET example_basic PROPERTY RUNTIME_OUTPUT_DIRECTORY)

    message("example_basic location: ${example_basic_location}")

    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
        DEPENDS
        example_basic.build.yml
        example_basic.png
        example_basic_thumb.png
        ola_upload
        COMMENT "Force trigger rebuild when artifact files do change"
    )

    add_custom_command(TARGET example_basic PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.build.yml $<TARGET_FILE_DIR:example_basic>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.png $<TARGET_FILE_DIR:example_basic>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/example_basic_thumb.png $<TARGET_FILE_DIR:example_basic>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/ola_upload $<TARGET_FILE_DIR:example_basic>/ola_upload_example
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

    add_custom_command(TARGET example_basic POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:example_basic>/example_basic_dlls"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MSVCP_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${UCRTBASE_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${VCRUNTIME_1_DLL} $<TARGET_FILE_DIR:example_basic>/example_basic_dlls
    )
endif()