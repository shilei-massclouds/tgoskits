cmake_minimum_required(VERSION 3.20)
project(eventfd-linux-oracle C)

find_package(Threads REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "eventfd-linux-oracle requires a Linux host")
endif()
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    message(FATAL_ERROR "eventfd-linux-oracle requires an x86_64 host")
endif()
if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    message(FATAL_ERROR "eventfd-linux-oracle must target x86_64")
endif()

set(EVENTFD_ORACLE_ARTIFACT_DIR "$ENV{STARRY_EVENTFD_ORACLE_ARTIFACT_DIR}")

if(EVENTFD_ORACLE_ARTIFACT_DIR)
    if(NOT IS_ABSOLUTE "${EVENTFD_ORACLE_ARTIFACT_DIR}")
        message(FATAL_ERROR "STARRY_EVENTFD_ORACLE_ARTIFACT_DIR must be absolute")
    endif()
    if(NOT IS_DIRECTORY "${EVENTFD_ORACLE_ARTIFACT_DIR}")
        message(FATAL_ERROR
            "STARRY_EVENTFD_ORACLE_ARTIFACT_DIR is not a directory: ${EVENTFD_ORACLE_ARTIFACT_DIR}")
    endif()

    set(EVENTFD_ORACLE_ELF "${EVENTFD_ORACLE_ARTIFACT_DIR}/eventfd-linux-oracle")
    set(EVENTFD_ORACLE_CORPUS "${EVENTFD_ORACLE_ARTIFACT_DIR}/eventfd.ops")
    set(EVENTFD_ORACLE_TRACE "${EVENTFD_ORACLE_ARTIFACT_DIR}/linux.trace")
    foreach(ARTIFACT IN ITEMS
            "${EVENTFD_ORACLE_ELF}" "${EVENTFD_ORACLE_CORPUS}" "${EVENTFD_ORACLE_TRACE}")
        if(NOT EXISTS "${ARTIFACT}" OR IS_DIRECTORY "${ARTIFACT}")
            message(FATAL_ERROR "missing eventfd oracle artifact: ${ARTIFACT}")
        endif()
    endforeach()

    install(PROGRAMS "${EVENTFD_ORACLE_ELF}" DESTINATION usr/bin)
    install(
        FILES "${EVENTFD_ORACLE_CORPUS}" "${EVENTFD_ORACLE_TRACE}"
        DESTINATION usr/share/starry-tests/eventfd-linux-oracle
    )
else()
    set(EVENTFD_ORACLE_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/corpus/eventfd.ops")
    set(EVENTFD_ORACLE_TRACE "${CMAKE_CURRENT_BINARY_DIR}/linux.trace")

    set(LINUX_ORACLE_COMMON_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/../../linux-oracle-common")
    add_executable(
        eventfd-linux-oracle
        src/eventfd_linux_oracle.c
        src/eventfd_concurrent_oracle.c
        "${LINUX_ORACLE_COMMON_DIR}/controlled_worker.c"
        "${LINUX_ORACLE_COMMON_DIR}/concurrent_trace.c"
    )
    target_include_directories(
        eventfd-linux-oracle PRIVATE "${LINUX_ORACLE_COMMON_DIR}"
    )
    target_compile_options(eventfd-linux-oracle PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(eventfd-linux-oracle PRIVATE Threads::Threads)
    target_link_options(eventfd-linux-oracle PRIVATE -static)

    add_custom_command(
        OUTPUT "${EVENTFD_ORACLE_TRACE}"
        COMMAND $<TARGET_FILE:eventfd-linux-oracle>
                --record "${EVENTFD_ORACLE_CORPUS}" "${EVENTFD_ORACLE_TRACE}"
        DEPENDS eventfd-linux-oracle "${EVENTFD_ORACLE_CORPUS}"
        COMMENT "Recording eventfd results from the running host Linux"
        VERBATIM
    )
    add_custom_target(eventfd-linux-oracle-trace ALL DEPENDS "${EVENTFD_ORACLE_TRACE}")

    install(TARGETS eventfd-linux-oracle RUNTIME DESTINATION usr/bin)
    install(
        FILES "${EVENTFD_ORACLE_CORPUS}" "${EVENTFD_ORACLE_TRACE}"
        DESTINATION usr/share/starry-tests/eventfd-linux-oracle
    )
endif()
