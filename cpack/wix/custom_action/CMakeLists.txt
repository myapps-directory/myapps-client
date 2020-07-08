set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(ola_wix_custom_action MODULE
  uninstall_cleanup.cpp
  exports.def
)

target_link_libraries(ola_wix_custom_action PRIVATE msi)