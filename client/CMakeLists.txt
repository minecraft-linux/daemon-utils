cmake_minimum_required (VERSION 2.6)

project(daemon_client_utils LANGUAGES CXX)

add_library(daemon_client_utils include/daemon_utils/daemon_launcher.h src/daemon_launcher.cpp)
target_include_directories(daemon_client_utils PUBLIC include/)
target_link_libraries(daemon_client_utils logger simpleipc file_util)