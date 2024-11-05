#include_directories(${PROJECT_SOURCE_DIR}/lib/cryptopp  ${PROJECT_SOURCE_DIR}/src/common)

#find_package(CryptoPP REQUIRED)

# 手动指定头文件和库文件路径
set(CRYPTOPP_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/lib/cryptopp)
set(CRYPTOPP_LIBRARY ${PROJECT_SOURCE_DIR}/lib/cryptopp/libcryptopp.a)

# 包含目录
include_directories(${CRYPTOPP_INCLUDE_DIR}
                    ${PROJECT_SOURCE_DIR}/src/common)

if(WIN32)
  message(STATUS "windows compiling...")
  add_definitions(-D_PLATFORM_IS_WINDOWS_)
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
else(WIN32)
  message(STATUS "linux compiling...")
  add_definitions( -D_PLATFORM_IS_LINUX_)
endif(WIN32)

# 添加可执行文件
add_executable(
  license_demo
  common/LicenseUtils_demo.cpp
  main.cpp
)

# 链接库目录
link_directories(${CRYPTOPP_INCLUDE_DIR})

# 链接库
target_link_libraries(license_demo PRIVATE CRYPTOPP_LIBRARY)
