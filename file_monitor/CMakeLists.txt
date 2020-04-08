
if(WIN32)
    add_library(file_monitor file_monitor.hpp src/file_monitor_win.cpp)
    target_link_libraries(file_monitor
        solid_utility
        solid_system
    )
    add_subdirectory(test)
endif()