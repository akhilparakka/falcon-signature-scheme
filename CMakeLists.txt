cmake_minimum_required(VERSION 3.10)
project(falcon-signature)

set(FALCON_DIR ${CMAKE_SOURCE_DIR}/falcon)

include_directories(${FALCON_DIR})

link_directories(${FALCON_DIR})

add_executable(falcon-signature main.cpp)

target_link_libraries(falcon-signature ${FALCON_DIR}/libfalcon.a)
