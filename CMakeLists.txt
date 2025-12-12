cmake_minimum_required(VERSION 3.22)
project(protobuf2 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g3")

add_executable(protobuf2
        main.c
        protobuf.c
        protobuf.h
        influx.h
        influx_wire.c)
