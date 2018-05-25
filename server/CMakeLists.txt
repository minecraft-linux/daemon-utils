cmake_minimum_required (VERSION 2.6)

project(daemon_server_utils LANGUAGES CXX)

add_library(daemon_server_utils include/daemon_utils/auto_shutdown_service.h src/auto_shutdown_service.cpp)
target_include_directories(daemon_server_utils PUBLIC include/)
target_link_libraries(daemon_server_utils logger simpleipc file_util)