cmake_minimum_required(VERSION 3.20)
project(kerndiff_overlay NONE)

set(KERNDIFF_OVERLAY_DIR "$ENV{KERNDIFF_OVERLAY_DIR}")
if(KERNDIFF_OVERLAY_DIR STREQUAL "")
  message(FATAL_ERROR "KERNDIFF_OVERLAY_DIR is required")
endif()
if(NOT IS_ABSOLUTE "${KERNDIFF_OVERLAY_DIR}")
  message(FATAL_ERROR "KERNDIFF_OVERLAY_DIR must be absolute: ${KERNDIFF_OVERLAY_DIR}")
endif()
if(NOT IS_DIRECTORY "${KERNDIFF_OVERLAY_DIR}")
  message(FATAL_ERROR "KERNDIFF_OVERLAY_DIR is not a directory: ${KERNDIFF_OVERLAY_DIR}")
endif()

set(KERNDIFF_GUEST_RUNNER "${KERNDIFF_OVERLAY_DIR}/usr/libexec/kerndiff/run")
if(NOT EXISTS "${KERNDIFF_GUEST_RUNNER}")
  message(FATAL_ERROR "KernDiff overlay is missing /usr/libexec/kerndiff/run")
endif()
execute_process(
  COMMAND test -x "${KERNDIFF_GUEST_RUNNER}"
  RESULT_VARIABLE KERNDIFF_GUEST_RUNNER_STATUS
)
if(NOT KERNDIFF_GUEST_RUNNER_STATUS EQUAL 0)
  message(FATAL_ERROR "KernDiff overlay /usr/libexec/kerndiff/run must be executable")
endif()

install(DIRECTORY "${KERNDIFF_OVERLAY_DIR}/" DESTINATION "." USE_SOURCE_PERMISSIONS)
