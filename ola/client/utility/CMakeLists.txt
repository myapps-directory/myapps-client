add_library(ola_client_utility locale.hpp arrvec.hpp auth_file.hpp src/auth_file.cpp)
target_link_libraries(ola_client_utility solid_system)