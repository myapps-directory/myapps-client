list(APPEND CMAKE_PREFIX_PATH "${EXTERNAL_PATH}")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed
set(CMAKE_AUTOMOC ON)
# Create code from a list of Qt designer ui files
set(CMAKE_AUTOUIC ON)

set(Qt5Widgets_DIR ${QT5PREFIX_DIR}/Qt5Widgets)
set(Qt5Core_DIR ${QT5PREFIX_DIR}/Qt5Core)
set(Qt5Gui_DIR ${QT5PREFIX_DIR}/Qt5Gui)

message("Finding Qt5 from ${Qt5Widgets_DIR}")

find_package (Qt5Core)
find_package (Qt5Gui)
find_package (Qt5Widgets)

if(${Qt5Widgets_FOUND})
    QT5_WRAP_UI(FORMS_HEADERS auth_form.ui)
    
    set(SRCS
        auth_form.ui
        auth_main.cpp
        auth_widget.cpp
        auth_widget.hpp
		auth_protocol.hpp
        ${FORMS_HEADERS}
    )

    if(WIN32)
        set_source_files_properties(auth_main.cpp PROPERTIES COMPILE_FLAGS -bigobj)
        add_executable(
            ola_client_auth
            WIN32
            ${SRCS}
        )
    elseif(APPLE)
        add_executable(
            ola_client_auth
            MACOSX_BUNDLE
            ${SRCS}
        )
    else()
        add_executable(
            ola_client_auth
            ${SRCS}
        )
    endif()

    add_dependencies(ola_client_auth build-snappy build-cereal)

    target_link_libraries(
        ola_client_auth
		ola_utility
        solid_frame_mprpc
        solid_frame_aio_openssl
        solid_serialization_v2
        ${OPENSSL_LIBRARIES}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        Qt5::Widgets
        ${SNAPPY_LIB}
        ${SYS_BASIC_LIBS}
        ${SYS_DYNAMIC_LOAD_LIB}
    )

    add_custom_command(TARGET ola_client_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt5::Core> $<TARGET_FILE_DIR:ola_client_auth>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt5::Gui> $<TARGET_FILE_DIR:ola_client_auth>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt5::Widgets> $<TARGET_FILE_DIR:ola_client_auth>
        COMMAND ${CMAKE_COMMAND} -E copy_directory $<TARGET_FILE_DIR:Qt5::Widgets>/../plugins/platforms $<TARGET_FILE_DIR:ola_client_auth>/platforms
    )

    install(TARGETS ola_client_auth DESTINATION bin)
    install(FILES $<TARGET_FILE:Qt5::Core> DESTINATION bin)
    install(FILES $<TARGET_FILE:Qt5::Gui> DESTINATION bin)
    install(FILES $<TARGET_FILE:Qt5::Widgets> DESTINATION bin)
    install(DIRECTORY $<TARGET_FILE_DIR:ola_client_auth>/platforms DESTINATION bin)
endif()
