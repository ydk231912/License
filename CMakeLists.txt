# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.8)
# 项目信息
project (SoftWareLicense)
#
if(WIN32)
  message(STATUS "windows compiling...")
  add_definitions(-D_PLATFORM_IS_WINDOWS_)
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
else(WIN32)
  message(STATUS "linux compiling...")
  add_definitions( -D_PLATFORM_IS_LINUX_)
endif(WIN32)
#
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/src)
# 指定源文件的目录,并将名称保存到变量
SET(source_h
  ${PROJECT_SOURCE_DIR}/common/License.h
	${PROJECT_SOURCE_DIR}/common/ostype.h
  )
  
SET(source_cpp
  ${PROJECT_SOURCE_DIR}/common/License.cpp
	${PROJECT_SOURCE_DIR}/src/main.cpp
  )
  
#头文件目录
include_directories(${PROJECT_SOURCE_DIR}/common)
# 指定生成目标
add_executable(license_demo ${source_h} ${source_cpp})