cmake_minimum_required(VERSION 3.10)
project(lhverify)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
find_package(Botan 2.4.0 REQUIRED)
include_directories(${BOTAN_INCLUDE_DIRS})

add_subdirectory(src)