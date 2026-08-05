cmake_minimum_required(VERSION 3.20)
project(linux-oracle-controlled-worker C)

include(CTest)
find_package(Threads REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_executable(
    controlled-worker-test
    controlled_worker.c
    tests/controlled_worker_test.c
)
target_compile_options(controlled-worker-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(controlled-worker-test PRIVATE Threads::Threads)
target_link_options(
    controlled-worker-test
    PRIVATE
        -Wl,--wrap=pthread_create
        -Wl,--wrap=pthread_join
        -Wl,--wrap=clock_gettime
        -Wl,--wrap=nanosleep
)
add_test(NAME controlled-worker-test COMMAND controlled-worker-test)

add_executable(
    concurrent-trace-test
    concurrent_trace.c
    tests/concurrent_trace_test.c
)
target_compile_options(concurrent-trace-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME concurrent-trace-test COMMAND concurrent-trace-test)
