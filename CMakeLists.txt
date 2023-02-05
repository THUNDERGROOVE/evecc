cmake_minimum_required(VERSION 3.20)

option(SKIP_AUTOMATE_VCPKG "When ON, you will need to built the packages required by evecc on \
your own or supply your own vcpkg toolchain.")

if (NOT SKIP_AUTOMATE_VCPKG)
    include(cmake/automate-vcpkg.cmake)

    vcpkg_bootstrap()
    vcpkg_install_packages(loguru python2 zlib)
endif()

project(evecc)

set(CMAKE_CXX_STANDARD 17)

set(evecc_src
        src/main.cpp
        src/scripts.h
        src/bluecrypto.cpp
        src/bluecrypto.h
        src/blue_module.h
        src/blue_module.cpp
        src/util.cpp
        src/util.h
        src/ini.cpp
        src/ini.h
        src/INIReader.cpp
        src/INIReader.h
        src/commands.cpp src/commands.h)

add_executable(evecc ${evecc_src})

target_include_directories(evecc PUBLIC SYSTEM "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include/")
#target_link_libraries(evecc PRIVATE ZLIB::ZLIB)

find_package(Python2 COMPONENTS Development)
target_include_directories(evecc PUBLIC SYSTEM "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include/python2.7/")

target_include_directories(evecc PUBLIC SYSTEM "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include" "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/src/")
target_link_directories(evecc PRIVATE "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib" )

add_custom_target(evecc_release_zip COMMAND
        "C:/Program Files/7-Zip/7z.exe" "a" "-t7z" "evecc-${CMAKE_BUILD_TYPE}.7z"
        "${CMAKE_CURRENT_BINARY_DIR}/evecc.exe"
        "${CMAKE_CURRENT_BINARY_DIR}/python27.dll"
        "${CMAKE_CURRENT_BINARY_DIR}/zlib1.dll"
        "${CMAKE_CURRENT_SOURCE_DIR}/readme.md"
        )


