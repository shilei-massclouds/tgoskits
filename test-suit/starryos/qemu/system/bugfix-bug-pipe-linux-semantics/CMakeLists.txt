cmake_minimum_required(VERSION 3.20)
project(bugfix-bug-pipe-linux-semantics C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_executable(bugfix-bug-pipe-linux-semantics src/main.c)
target_compile_options(bugfix-bug-pipe-linux-semantics PRIVATE -Wall -Wextra -Werror)
install(
    TARGETS bugfix-bug-pipe-linux-semantics
    RUNTIME DESTINATION usr/bin/starry-test-suit
)
