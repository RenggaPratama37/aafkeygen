cmake_minimum_required(VERSION 3.16)

project(gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_AUTOUIC_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(GUI_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/vault_view.cpp
    src/vault_view.h
    ui/mainwindow.ui
    ui/vault_view.ui
    ui/dialog.ui
)

if(QT_VERSION_MAJOR GREATER_EQUAL 6)
    qt_add_executable(gui
        ${GUI_SOURCES}
    )
else()
    add_executable(gui
        ${GUI_SOURCES}
        src/passworddialog.h
        src/passworddialog.cpp
    )
endif()

target_include_directories(gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(gui PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
)

set_target_properties(gui PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)
