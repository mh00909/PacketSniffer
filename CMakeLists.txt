cmake_minimum_required(VERSION 3.28)
project(packetsniffer C)

set(CMAKE_C_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK REQUIRED gtk+-3.0)

include_directories(${GTK_INCLUDE_DIRS})
link_directories(${GTK_LIBRARY_DIRS})
add_definitions(${GTK_CFLAGS_OTHER})


add_executable(packetsniffer main.c

        packet_handler.h
        packet_handler.c
        gui.c
        gui.h
        app_data.h

)
