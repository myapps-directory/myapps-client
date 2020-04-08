
set( file_monitorTestSuite
    test_file_monitor_basic.cpp
)
#
create_test_sourcelist( file_monitorTests test_file_monitor.cpp ${file_monitorTestSuite})

add_executable(test_file_monitor ${file_monitorTests})

target_link_libraries(test_file_monitor
solid_utility
solid_system
file_monitor
${Boost_FILESYSTEM_LIBRARY}
${SYSTEM_DYNAMIC_LOAD_LIBRARY}
${SYSTEM_BASIC_LIBRARIES}
Threads::Threads
)

add_test(NAME Testfile_monitorBasic       COMMAND  test_file_monitor test_file_monitor_basic)
