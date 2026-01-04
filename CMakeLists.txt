cmake_minimum_required(VERSION 3.16)

project(aafkeygen VERSION 2.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_ENGINE "Build the engine library" ON)
option(BUILD_CLI "Build the CLI" ON)
option(BUILD_GUI "Build the GUI" ON)

if(BUILD_ENGINE)
	add_subdirectory(libs/engine)
endif()

if(BUILD_CLI)
	add_subdirectory(cli)
endif()

if(BUILD_GUI)
	add_subdirectory(gui)
endif()
