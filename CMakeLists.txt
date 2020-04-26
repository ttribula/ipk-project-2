cmake_minimum_required(VERSION 3.10)
project(IPK C)
set(PROG ipk-sniffer)
set(FILES_MAIN ipk-sniffer.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -std=c99 -pedantic -lm")
add_executable(${PROG} ${FILES_MAIN})