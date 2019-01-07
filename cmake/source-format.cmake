# additional target to perform clang-format run, requires clang-format

# get all project files
file(GLOB_RECURSE ALL_SOURCE_FILES ola/*.hpp ola/*.cpp)
foreach (SOURCE_FILE ${ALL_SOURCE_FILES})
    #message("Source file: ${SOURCE_FILE}")
    string(FIND ${SOURCE_FILE} ${CMAKE_CURRENT_BINARY_DIR} PROJECT_TRDPARTY_DIR_FOUND)
    if (NOT ${PROJECT_TRDPARTY_DIR_FOUND} EQUAL -1)
        list(REMOVE_ITEM ALL_SOURCE_FILES ${SOURCE_FILE})
    else ()
    endif ()
endforeach ()

find_program(CLANG_FORMAT_BIN
    NAMES clang-format-6.0 clang-format
    PATHS /usr/local/bin /usr/bin
    NO_DEFAULT_PATH
)

add_custom_target(
    source-reformat
    COMMAND ${CLANG_FORMAT_BIN}
    -style=file
    -i
    ${ALL_SOURCE_FILES}
)
