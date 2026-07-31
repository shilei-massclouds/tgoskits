cmake_minimum_required(VERSION 3.20)
project(pipe-linux-oracle C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "pipe-linux-oracle requires a Linux host")
endif()
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    message(FATAL_ERROR "pipe-linux-oracle requires an x86_64 host")
endif()
if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    message(FATAL_ERROR "pipe-linux-oracle must target x86_64")
endif()

set(PIPE_ORACLE_ARTIFACT_DIR "$ENV{STARRY_PIPE_ORACLE_ARTIFACT_DIR}")

if(PIPE_ORACLE_ARTIFACT_DIR)
    if(NOT IS_ABSOLUTE "${PIPE_ORACLE_ARTIFACT_DIR}")
        message(FATAL_ERROR "STARRY_PIPE_ORACLE_ARTIFACT_DIR must be absolute")
    endif()
    if(NOT IS_DIRECTORY "${PIPE_ORACLE_ARTIFACT_DIR}")
        message(FATAL_ERROR
            "STARRY_PIPE_ORACLE_ARTIFACT_DIR is not a directory: ${PIPE_ORACLE_ARTIFACT_DIR}")
    endif()

    set(PIPE_ORACLE_ELF "${PIPE_ORACLE_ARTIFACT_DIR}/pipe-linux-oracle")
    set(PIPE_ORACLE_CORPUS "${PIPE_ORACLE_ARTIFACT_DIR}/pipe.ops")
    set(PIPE_ORACLE_TRACE "${PIPE_ORACLE_ARTIFACT_DIR}/linux.trace")
    foreach(ARTIFACT IN ITEMS
            "${PIPE_ORACLE_ELF}" "${PIPE_ORACLE_CORPUS}" "${PIPE_ORACLE_TRACE}")
        if(NOT EXISTS "${ARTIFACT}" OR IS_DIRECTORY "${ARTIFACT}")
            message(FATAL_ERROR "missing pipe oracle artifact: ${ARTIFACT}")
        endif()
    endforeach()

    install(PROGRAMS "${PIPE_ORACLE_ELF}" DESTINATION usr/bin)
    install(
        FILES "${PIPE_ORACLE_CORPUS}" "${PIPE_ORACLE_TRACE}"
        DESTINATION usr/share/starry-tests/pipe-linux-oracle
    )
else()
    set(PIPE_ORACLE_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/corpus/pipe.ops")
    set(PIPE_ORACLE_TRACE "${CMAKE_CURRENT_BINARY_DIR}/linux.trace")

    add_executable(pipe-linux-oracle src/pipe_linux_oracle.c)
    target_compile_options(pipe-linux-oracle PRIVATE -Wall -Wextra -Werror)
    target_link_options(pipe-linux-oracle PRIVATE -static)

    add_custom_command(
        OUTPUT "${PIPE_ORACLE_TRACE}"
        COMMAND $<TARGET_FILE:pipe-linux-oracle>
                --record "${PIPE_ORACLE_CORPUS}" "${PIPE_ORACLE_TRACE}"
        DEPENDS pipe-linux-oracle "${PIPE_ORACLE_CORPUS}"
        COMMENT "Recording pipe results from the running host Linux"
        VERBATIM
    )
    add_custom_target(pipe-linux-oracle-trace ALL DEPENDS "${PIPE_ORACLE_TRACE}")

    install(TARGETS pipe-linux-oracle RUNTIME DESTINATION usr/bin)
    install(
        FILES "${PIPE_ORACLE_CORPUS}" "${PIPE_ORACLE_TRACE}"
        DESTINATION usr/share/starry-tests/pipe-linux-oracle
    )
endif()
