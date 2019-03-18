list(APPEND CMAKE_PREFIX_PATH "${EXTERNAL_PATH}")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed
set(CMAKE_AUTOMOC ON)
# Create code from a list of Qt designer ui files
set(CMAKE_AUTOUIC ON)


find_package(Qt5Widgets)

if(${Qt5Widgets_FOUND})
    set(src_basic_gui
        gui_main.cpp
        gui_auth_widget.cpp
        gui_auth_widget.hpp
        gui_auth_form.ui
    )

    if(WIN32)  
        add_executable(
            ola_client_gui
            WIN32
            ${src_basic_gui}
        )
    elseif(APPLE)
        add_executable(
            ola_client_gui
            MACOSX_BUNDLE
            ${src_basic_gui}
        )
    else()
        add_executable(
            ola_client_gui
            ${src_basic_gui}
        )
    endif()

    add_dependencies(ola_client_gui build-snappy)

    target_link_libraries(
        ola_client_gui
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
endif()
