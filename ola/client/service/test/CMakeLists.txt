set( ClientServiceTests
    test_file_cache_file.cpp
    test_file_namefy.cpp
)

create_test_sourcelist(
    Tests test_client_service.cpp ${ClientServiceTests})

add_executable(
    test_client_service
    ${Tests}
    ../file_cache.hpp
    ../file_cache.cpp
)

target_link_libraries(test_client_service
    solid_system
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)

#add_dependencies(test_client_service build-cereal)

#add_test(NAME TestSystemNanoTime        COMMAND  test_system test_nanotime)