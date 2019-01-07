set(SolidFrame_DIR "${EXTERNAL_PATH}/lib/cmake/SolidFrame" CACHE PATH "SolidFrame CMake configuration dir")
find_package(SolidFrame 5)

if(SolidFrame_FOUND)
    message("\n-- SolidFrame version: ${SolidFrame_VERSION}\n")
else()
    message(FATAL_ERROR "\nSolidFrame not found!\n")
endif()
