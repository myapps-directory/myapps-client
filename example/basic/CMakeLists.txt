if(WIN32)

    add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic.build ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic.media ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic.png ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic_thumb.png
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.build ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.media ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.png ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/example_basic_thumb.png ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.build ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.media ${CMAKE_CURRENT_SOURCE_DIR}/example_basic.png ${CMAKE_CURRENT_SOURCE_DIR}/example_basic_thumb.png
    )

    add_custom_target(copy_upload
        DEPENDS
        ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic.build
        ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic.media
        ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic.png
        ${PROJECT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}/example_basic_thumb.png
    )

    set_source_files_properties(example_basic_win.cpp PROPERTIES COMPILE_FLAGS -bigobj)
    add_executable(
        example_basic
        WIN32
        example_basic_win.cpp
    )
    add_dependencies(example_basic copy_upload)
endif()