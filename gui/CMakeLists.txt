cmake_minimum_required(VERSION 3.16)

project(gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Auto tools
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_AUTOUIC_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
)

# Qt
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

# Sources
set(GUI_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/settingspage.h
    src/settingpage.cpp
    src/registerpage.cpp
    src/registerpage.h
    src/vault_view.cpp
    src/vault_view.h
    src/passworddialog.cpp
    src/passworddialog.h
    src/loginsetup.cpp
    src/loginsetup.h
    src/vault_model.cpp
    src/vault_model.h
    src/vaultfilterproxy.cpp
    src/vaultfilterproxy.h
    ui/mainwindow.ui
    ui/vault_view.ui
    ui/passworddialog.ui
    ui/settingspage.ui
    ui/registerpage.ui
)

# Executable
if(QT_VERSION_MAJOR GREATER_EQUAL 6)
    qt_add_executable(aafkeygen_gui
        ${GUI_SOURCES}
    )
else()
    add_executable(aafkeygen_gui
        ${GUI_SOURCES}
    )
endif()

# Include directories
target_include_directories(aafkeygen_gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link Qt Widgets
target_link_libraries(aafkeygen_gui PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
)

# Link engine if available from top-level project
if(TARGET engine)
    target_link_libraries(aafkeygen_gui PRIVATE engine)
endif()

# Output & bundle settings
set_target_properties(aafkeygen_gui PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

include(GNUInstallDirs)

install(TARGETS aafkeygen_gui
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
