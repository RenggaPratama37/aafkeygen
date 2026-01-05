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

# Packaging via CPack
include(GNUInstallDirs)

set(CPACK_PACKAGE_NAME "aafkeygen")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "you@example.com")
set(CPACK_PACKAGE_DESCRIPTION "AAF keygen - secure file encryption tools (CLI + GUI)")

# Default generator: DEB (can be changed by user)
set(CPACK_GENERATOR "DEB")

# Debian package dependencies (best-effort; users may need to adjust)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "zlib1g, libssl3")

include(CPack)
