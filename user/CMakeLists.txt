cmake_minimum_required(VERSION 3.0.0)
project(hyquic VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost 1.84.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
include_directories(./include/asio-1.28.0/include)

include(CTest)
enable_testing()

add_library(hyquic INTERFACE)
target_include_directories(hyquic INTERFACE .)

add_executable(tmp tmp.cpp)
target_link_libraries(tmp PUBLIC hyquic)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)