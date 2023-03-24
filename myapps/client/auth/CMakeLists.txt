list(APPEND CMAKE_PREFIX_PATH "${EXTERNAL_PATH}")
list(PREPEND CMAKE_PREFIX_PATH "${QTPREFIX_DIR}")

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Instruct CMake to run moc automatically when needed
set(CMAKE_AUTOMOC ON)

# Create code from a list of Qt designer ui files
set(CMAKE_AUTOUIC ON)


find_package(Qt6 REQUIRED COMPONENTS Core Widgets Gui)
qt6_standard_project_setup()

if(Qt6_FOUND AND WIN32 AND NOT TARGET Qt6::windeployqt)
    message("Finding Qt6 windeployqt")
    get_target_property(_qt6_qmake_location Qt6::qmake IMPORTED_LOCATION)

    execute_process(
        COMMAND "${_qt6_qmake_location}" -query QT_INSTALL_PREFIX
        RESULT_VARIABLE return_code
        OUTPUT_VARIABLE qt6_install_prefix
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    set(imported_location "${qt6_install_prefix}/bin/windeployqt.exe")

    if(EXISTS ${imported_location})
        add_executable(Qt6::windeployqt IMPORTED)

        set_target_properties(Qt6::windeployqt PROPERTIES
            IMPORTED_LOCATION ${imported_location}
        )
    endif()
endif()

if(${Qt6Widgets_FOUND})
    QT6_WRAP_UI(FORMS_HEADERS main_form.ui home_form.ui create_form.ui about_form.ui amend_form.ui reset_form.ui)
    QT6_ADD_RESOURCES( FORMS_HEADERS main_form.qrc)
    
    set(SRCS
        main_form.ui
        auth_main.cpp
        main_window.cpp
        main_window.hpp
        ${FORMS_HEADERS}
    )

    if(WIN32)
        add_executable(
            myapps_auth
            WIN32
            ${SRCS}
            auth_main.rc
        )
        if(TARGET Qt6::windeployqt)
            if(CMAKE_BUILD_TYPE MATCHES "debug")
                set(BUILD_TYPE "--debug")
            else()
                set(BUILD_TYPE "--release")
            endif()
            # execute windeployqt in a tmp directory after build
            add_custom_command(TARGET myapps_auth
                POST_BUILD
                #COMMAND ${CMAKE_COMMAND} -E remove_directory $<TARGET_FILE_DIR:ola_client_store>/windeployqt
                COMMAND set PATH=%PATH%$<SEMICOLON>${qt6_install_prefix}/bin
                COMMAND Qt6::windeployqt ${BUILD_TYPE} "$<TARGET_FILE_DIR:myapps_auth>/$<TARGET_FILE_NAME:myapps_auth>"
            )

            # copy deployment directory during installation
            install(DIRECTORY $<TARGET_FILE_DIR:myapps_auth>//windeployqt/ DESTINATION bin PATTERN "windeployqt/*")
        endif()
        set_source_files_properties(auth_main.cpp PROPERTIES COMPILE_FLAGS "-DMYAPPS_FRONT_URL=\\\"${MYAPPS_FRONT_URL}\\\" -bigobj")
    elseif(APPLE)
        add_executable(
            myapps_auth
            MACOSX_BUNDLE
            ${SRCS}
        )
    else()
        add_executable(
            myapps_auth
            ${SRCS}
        )
    endif()

    add_dependencies(myapps_auth build-snappy build-cereal)
    set_target_properties(
        myapps_auth PROPERTIES
        VS_DEBUGGER_WORKING_DIRECTORY $<TARGET_FILE_DIR:myapps_auth>)

    target_link_libraries(
        myapps_auth
        myapps_client_utility
		myapps_utility
        SolidFrame::solid_frame_mprpc
        SolidFrame::solid_frame_aio_openssl
        SolidFrame::solid_serialization_v3
        Boost::program_options
        Boost::system
        Qt::Widgets
        ${SNAPPY_LIB}
        ${SYS_BASIC_LIBS}
        ${SYS_DYNAMIC_LOAD_LIB}
    )

    if(TARGET Qt6::windeployqt)
        if(CMAKE_BUILD_TYPE MATCHES "debug")
            set(BUILD_TYPE "--debug")
        else()
            set(BUILD_TYPE "--release")
        endif()
        # execute windeployqt in a tmp directory after build
        add_custom_command(TARGET myapps_auth
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E remove_directory $<TARGET_FILE_DIR:myapps_auth>/windeployqt
            COMMAND set PATH=%PATH%$<SEMICOLON>${qt6_install_prefix}/bin
            COMMAND Qt6::windeployqt ${BUILD_TYPE} --dir $<TARGET_FILE_DIR:myapps_auth>//windeployqt "$<TARGET_FILE_DIR:myapps_auth>/$<TARGET_FILE_NAME:myapps_auth>"
        )

        # copy deployment directory during installation
        install(DIRECTORY $<TARGET_FILE_DIR:myapps_auth>/windeployqt/ DESTINATION bin PATTERN "windeployqt/*")
    endif()

    add_custom_command(TARGET myapps_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/myapps/client/utility/certs  $<TARGET_FILE_DIR:myapps_auth>/certs
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_SSL_DLL} $<TARGET_FILE_DIR:myapps_auth>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_CRYPTO_DLL} $<TARGET_FILE_DIR:myapps_auth>
    )

    install(TARGETS myapps_auth DESTINATION bin)
    install(FILES ${OPENSSL_SSL_DLL} DESTINATION bin)
    install(FILES ${OPENSSL_CRYPTO_DLL} DESTINATION bin)
endif()
