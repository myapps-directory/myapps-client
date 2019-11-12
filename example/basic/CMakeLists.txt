if(WIN32)
    set_source_files_properties(example_basic_win.cpp PROPERTIES COMPILE_FLAGS -bigobj)
    add_executable(
        example_basic
        WIN32
        example_basic_win.cpp
    )
endif()