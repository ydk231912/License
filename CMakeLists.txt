# CMake 最低版本号要求
cmake_minimum_required (VERSION 3.10)
# 项目信息
project (license)
# 设置C++版本
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE debug)

add_subdirectory(src)