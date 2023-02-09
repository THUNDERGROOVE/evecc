set(GIT_HASH "unknown")

find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --always
            OUTPUT_VARIABLE GIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
    )
endif()

message(STATUS "git hash is ${GIT_HASH}")

configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/version.h.in
        ${TARGET_DIR}/gen/version.h
        @ONLY
)