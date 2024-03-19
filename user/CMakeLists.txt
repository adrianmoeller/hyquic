cmake_minimum_required(VERSION 3.0.0)
project(hyquic VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost 1.84.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

add_library(hyquic INTERFACE)
target_include_directories(hyquic INTERFACE .)
target_link_libraries(hyquic INTERFACE quic)

# TESTING

include(CTest)
enable_testing()

set(TESTS_DIR ${CMAKE_SOURCE_DIR}/tests)
set(KEYS_DIR ${TESTS_DIR}/keys)
set(SERVER_CLIENT_TEST_RUNNER ${TESTS_DIR}/run_test_sudo.sh -s "0.0.0.0 1234 ${KEYS_DIR}/server-key-u.pem ${KEYS_DIR}/server-cert-u.pem" -c "127.0.0.1 1234")

add_executable(buffer_test tests/buffer_test.cpp)
target_link_libraries(buffer_test PUBLIC hyquic)

add_executable(sample_test tests/sample_test.cpp)
target_link_libraries(sample_test PUBLIC hyquic)

add_executable(ffs_test tests/ffs_test.cpp)
target_link_libraries(ffs_test PUBLIC hyquic)

add_test(buffer_test buffer_test)
add_test(sample_test ${SERVER_CLIENT_TEST_RUNNER} sample_test)
add_test(ffs_test ${SERVER_CLIENT_TEST_RUNNER} -a 0 ffs_test)

# PACKAGING

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)