cmake_minimum_required(VERSION 3.13)

project(apsi_example VERSION 1.0)

find_package(APSI)

add_executable(apsi_example main.cpp)
target_link_libraries(apsi_example APSI::apsi)
