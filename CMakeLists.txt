cmake_minimum_required(VERSION 3.16)
project(cifrado VERSION 2.0.0 LANGUAGES CXX)

include(GNUInstallDirs)
set(CIFRADO_APP_ID "io.github.Francisco_LP.Cifrado")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(CIFRADO_BUILD_GUI "Compilar la aplicación de escritorio (Qt 6)" ON)
option(CIFRADO_BUILD_TESTS "Compilar los tests" ON)

# Argon2id está disponible en OpenSSL desde la versión 3.2.
find_package(OpenSSL 3.2 REQUIRED)

# --- Núcleo compartido -------------------------------------------------------
add_library(cifrado_core STATIC core/cifrado.cpp)
target_include_directories(cifrado_core PUBLIC core)
target_link_libraries(cifrado_core PUBLIC OpenSSL::Crypto)
target_compile_options(cifrado_core PRIVATE -Wall -Wextra)

# --- CLI ---------------------------------------------------------------------
add_executable(cifrado cli/main.cpp)
target_link_libraries(cifrado PRIVATE cifrado_core)
install(TARGETS cifrado RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# --- GUI ---------------------------------------------------------------------
if(CIFRADO_BUILD_GUI)
  find_package(Qt6 COMPONENTS Widgets)
  if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    add_executable(cifrado-gui gui/main.cpp gui/mainwindow.cpp gui/mainwindow.hpp
                               gui/theme.cpp gui/theme.hpp)
    target_link_libraries(cifrado-gui PRIVATE cifrado_core Qt6::Widgets)
    install(TARGETS cifrado-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES data/${CIFRADO_APP_ID}.desktop
            DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
    install(FILES data/${CIFRADO_APP_ID}.svg
            DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
    install(FILES data/${CIFRADO_APP_ID}.metainfo.xml
            DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo)
  else()
    message(WARNING "Qt 6 no encontrado: solo se compilará la CLI. "
                    "En Fedora: sudo dnf install qt6-qtbase-devel")
  endif()
endif()

# --- Tests -------------------------------------------------------------------
if(CIFRADO_BUILD_TESTS)
  enable_testing()
  add_executable(cifrado_tests tests/test_core.cpp)
  target_link_libraries(cifrado_tests PRIVATE cifrado_core)
  add_test(NAME core COMMAND cifrado_tests)
endif()
