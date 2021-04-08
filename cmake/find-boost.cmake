add_custom_target(external_build_boost)

    set(BOOST_ROOT "${EXTERNAL_DIR}")
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_MULTITHREADED ON)
    #set(Boost_USE_STATIC_RUNTIME ON)

    find_package(Boost
        COMPONENTS
            system
            chrono
            thread
            filesystem
            program_options
    )
