cmake_minimum_required(VERSION 3.16)

project(engine LANGUAGES C)

include(GNUInstallDirs)

file(GLOB ENGINE_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
add_library(engine STATIC ${ENGINE_SRCS})

target_include_directories(engine PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# External dependencies used by the engine (compression and crypto)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

target_link_libraries(engine PUBLIC OpenSSL::Crypto ZLIB::ZLIB)

install(TARGETS engine
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
