cmake_minimum_required(VERSION 3.20)
project(evecc)

set(CMAKE_CXX_STANDARD 17)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

set(BUILD_SHARED_LIBS OFF)
set(CRC32C_BUILD_TESTS OFF)
set(CRC32C_BUILD_BENCHMARKS OFF)
set(CRC32C_USE_GLOG OFF)
add_subdirectory(vendor/crc32c)

add_subdirectory(vendor/loguru)

SET(PYTHON_VERSION "2.7.13" CACHE STRING "")
set(BUILD_EXTENSIONS_AS_BUILTIN ON CACHE BOOL "")
set(BUILTIN_UNICODEDATA ON CACHE BOOL "")
add_subdirectory(vendor/python-cmake-buildsystem)

set(evecc_src
        src/main.cpp
        src/scripts.h
        src/bluecrypto.cpp
        src/bluecrypto.h
        src/blue_module.h
        src/blue_module.cpp
        src/util.cpp
        src/util.h
        src/commands.cpp
        src/commands.h
        src/py_build_cache.cpp
        src/py_build_cache.h

        vendor/inih/ini.c
        vendor/inih/ini.h
        vendor/inih/cpp/INIReader.cpp
        vendor/inih/cpp/INIReader.h
)

# Custom target to bake the git hash into the executable
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gen/version.h
        ALL
        COMMAND
        ${CMAKE_COMMAND} -D TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/git.cmake
        WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(git_hash ALL DEPENDS ${CMAKE_BINARY_DIR}/gen/version.h)

# Custom target to create a release zip using 7zip - this requires that 7zip is installed to the default location
add_custom_target(evecc_release_zip COMMAND
        "C:/Program Files/7-Zip/7z.exe" "a" "-t7z" "evecc-${CMAKE_BUILD_TYPE}.7z"
        "${CMAKE_CURRENT_BINARY_DIR}/evecc.exe"
        "${CMAKE_CURRENT_SOURCE_DIR}/readme.md"
        "${CMAKE_CURRENT_BINARY_DIR}/Python"
)


# Custom target to create the folder of python dependencies
add_custom_command(
        OUTPUT Python/Lib
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_BINARY_DIR}/vendor/Python-2.7.13/Lib ${CMAKE_CURRENT_BINARY_DIR}/Python/Lib
        DEPENDS ${CMAKE_BINARY_DIR}/vendor/Python-2.7.13/Lib
)
add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/Python/uncompyle6.zip
        COMMAND "${CMAKE_COMMAND}" -E tar cvf ${CMAKE_CURRENT_BINARY_DIR}/Python/uncompyle6.zip --format=zip uncompyle6/
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/vendor/uncompyle6
        DEPENDS ${CMAKE_SOURCE_DIR}/vendor/uncompyle6/uncompyle6
)
add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/Python/uncompyle2.zip
        COMMAND "${CMAKE_COMMAND}" -E tar cvf ${CMAKE_CURRENT_BINARY_DIR}/Python/uncompyle2.zip --format=zip uncompyle2/
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/vendor/uncompyle2
        DEPENDS ${CMAKE_SOURCE_DIR}/vendor/uncompyle2/uncompyle2
)

add_custom_target(evecc_python_dependencies ALL
        DEPENDS ${PROJECT_BINARY_DIR}/Python/Lib ${PROJECT_BINARY_DIR}/Python/uncompyle2.zip ${PROJECT_BINARY_DIR}/Python/uncompyle6.zip)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/Python)


add_executable(evecc ${evecc_src})
add_dependencies(evecc libpython-static python git_hash)

target_include_directories(evecc PRIVATE vendor)
target_include_directories(evecc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/gen)
target_include_directories(evecc PUBLIC SYSTEM "${CMAKE_BINARY_DIR}/vendor/python-cmake-buildsystem/include")
target_include_directories(evecc PUBLIC SYSTEM "${CMAKE_BINARY_DIR}/vendor/python-cmake-buildsystem/bin/PC")
target_link_directories(evecc PUBLIC "${CMAKE_BINARY_DIR}/vendor/python-cmake-buildsystem/static-libs")
target_link_libraries(evecc PRIVATE "python27.lib" crc32c)

target_include_directories(evecc PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/src/")

add_dependencies(evecc evecc_python_dependencies)
add_dependencies(evecc_release_zip evecc)
