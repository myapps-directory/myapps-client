set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(myapps_wix_custom_action MODULE
  uninstall_cleanup.cpp
  exports.def
)

target_link_libraries(myapps_wix_custom_action PRIVATE msi)

add_library(myapps_wix_install_custom_action MODULE
  install_validations.cpp
  install_exports.def
)

target_link_libraries(myapps_wix_install_custom_action PRIVATE msi)