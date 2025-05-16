# 设置 CMake 最低版本号
cmake_minimum_required(VERSION 3.10)

# 设置工程名称
project(myNetlib)

# 设定编译参数
set(CMAKE_C_STANDARD 17) # 指定 C 版本
set(CMAKE_CXX_STANDARD 17) # 指定 C++ 版本
set(CMAKE_BUILD_TYPE "Debug") # 调试使用Debug，可以查看中间变量；发布使用Release，运行速度快，本质是两组预定义的编译器参数

# add_compile_options(-std=c++11 -Wall -Werror)

# 设定源码列表,查找指定目录(都放在./src/中)中的所有源文件,并将名称保存到 DIR_SRC 变量中
aux_source_directory(./src/ DIR_SRC)

# 设定头文件路径（还可以增加其他第三方库的头文件路径）
include_directories(./include/)

# # 添加头文件路径，用于编译可执行文件
# include_directories(./source/add
#                     ./source/sub
#                     ./source/mul)

# # 查找第三方库头文件目录
# find_package(OpenCV REQUIRED) 
# include_directories(${OpenCV_INCLUDE_DIRS})
# # 实际上会调用官方预定义好的<LibaryName>.cmake命名的文件
# # 一般会定义以下几个变量：<LibaryName>_FOUND（找到与否）<LibaryName>_INCLUDE_DIRS等

# 把源码编译成一个可执行文件，文件名为test，会保存在当前目录下
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)  # 设置可执行文件的输出目录
add_executable( test ${DIR_SRC} ) 

# # 可执行文件名 动态链接第三方库
# target_link_libraries(test ${OpenCV_LIBS} )
target_link_libraries(test pcap)