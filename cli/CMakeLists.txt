cmake_minimum_required(VERSION 3.16)

project(aafkeygen_cli LANGUAGES C)

file(GLOB CLI_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
add_executable(aafkeygen_cli ${CLI_SRCS})

target_include_directories(aafkeygen_cli PRIVATE ${CMAKE_SOURCE_DIR}/libs/engine/include)
target_link_libraries(aafkeygen_cli PRIVATE engine)

install(TARGETS aafkeygen_cli
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
