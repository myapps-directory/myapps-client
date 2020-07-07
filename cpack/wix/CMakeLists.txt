add_subdirectory(custom_action)

set(CUSTOM_ACTION_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/custom_action_dll.wxs")

file(GENERATE
  OUTPUT "${CUSTOM_ACTION_OUTPUT}"
  INPUT "${CMAKE_CURRENT_SOURCE_DIR}/custom_action_dll.wxs.in"
  )
