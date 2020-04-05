list(APPEND CMAKE_PREFIX_PATH "${EXTERNAL_PATH}")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed
set(CMAKE_AUTOMOC ON)
# Create code from a list of Qt designer ui files
set(CMAKE_AUTOUIC ON)

set(Qt5_DIR ${QT5PREFIX_DIR}/Qt5)

message("Finding Qt5 from ${Qt5_DIR}")
find_package(Qt5 COMPONENTS Core Widgets Gui)

if(Qt5_FOUND AND WIN32 AND NOT TARGET Qt5::windeployqt)
    message("Finding Qt5 windeployqt")
    get_target_property(_qt5_qmake_location Qt5::qmake IMPORTED_LOCATION)

    execute_process(
        COMMAND "${_qt5_qmake_location}" -query QT_INSTALL_PREFIX
        RESULT_VARIABLE return_code
        OUTPUT_VARIABLE qt5_install_prefix
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    set(imported_location "${qt5_install_prefix}/bin/windeployqt.exe")

    if(EXISTS ${imported_location})
        add_executable(Qt5::windeployqt IMPORTED)

        set_target_properties(Qt5::windeployqt PROPERTIES
            IMPORTED_LOCATION ${imported_location}
        )
    endif()
endif()

if(${Qt5Widgets_FOUND})
    QT5_WRAP_UI(FORMS_HEADERS main_form.ui home_form.ui create_form.ui about_form.ui amend_form.ui reset_form.ui)
    QT5_ADD_RESOURCES( FORMS_HEADERS main_form.qrc)
    
    set(SRCS
        main_form.ui
        auth_main.cpp
        main_window.cpp
        main_window.hpp
	    auth_protocol.hpp
        ${FORMS_HEADERS}
    )

    if(WIN32)
        add_executable(
            ola_client_auth
            WIN32
            ${SRCS}
            auth_main.rc
        )
        set_source_files_properties(auth_main.cpp PROPERTIES COMPILE_FLAGS "-DOLA_FRONT_URL=\\\"${OLA_FRONT_URL}\\\" -bigobj")
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

    if(TARGET Qt5::windeployqt)
        if(CMAKE_BUILD_TYPE MATCHES "debug")
            set(BUILD_TYPE "--debug")
        else()
            set(BUILD_TYPE "--release")
        endif()
        # execute windeployqt in a tmp directory after build
        add_custom_command(TARGET ola_client_auth
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E remove_directory $<TARGET_FILE_DIR:ola_client_auth>/windeployqt
            COMMAND set PATH=%PATH%$<SEMICOLON>${qt5_install_prefix}/bin
            COMMAND Qt5::windeployqt ${BUILD_TYPE} --dir $<TARGET_FILE_DIR:ola_client_auth>//windeployqt "$<TARGET_FILE_DIR:ola_client_auth>/$<TARGET_FILE_NAME:ola_client_auth>"
        )

        # copy deployment directory during installation
        install(DIRECTORY $<TARGET_FILE_DIR:ola_client_auth>/windeployqt/ DESTINATION bin PATTERN "windeployqt/*")
    endif()

    add_custom_command(TARGET ola_client_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_SSL_DLL} $<TARGET_FILE_DIR:ola_client_auth>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_CRYPTO_DLL} $<TARGET_FILE_DIR:ola_client_auth>
    )

    install(TARGETS ola_client_auth DESTINATION bin)
    install(FILES ${OPENSSL_SSL_DLL} DESTINATION bin)
    install(FILES ${OPENSSL_CRYPTO_DLL} DESTINATION bin)
endif()
