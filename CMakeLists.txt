cmake_minimum_required(VERSION 3.16)
project(SecureVaultGUI CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)

set(SOURCES
    src/main.cpp
    src/vault.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

if (WIN32)
    list(APPEND SOURCES src/vault_crypto_win.cpp)
else()
    list(APPEND SOURCES src/vault_crypto_openssl.cpp)
endif()

add_executable(securevault ${SOURCES})

target_include_directories(securevault PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

find_package(Threads REQUIRED)
target_link_libraries(securevault PRIVATE Threads::Threads)

if (WIN32)
    # GLFW + OpenGL are supplied manually for the mingw cross build via
    # SECUREVAULT_GLFW_DIR; native Windows users with vcpkg should instead
    # `find_package(glfw3 CONFIG REQUIRED)` and link glfw.
    if (DEFINED SECUREVAULT_GLFW_DIR)
        target_include_directories(securevault PRIVATE ${SECUREVAULT_GLFW_DIR}/include)
        target_link_libraries(securevault PRIVATE
            ${SECUREVAULT_GLFW_DIR}/lib/libglfw3.a
            opengl32 gdi32 bcrypt
        )
    else()
        find_package(glfw3 CONFIG REQUIRED)
        target_link_libraries(securevault PRIVATE glfw opengl32 gdi32 bcrypt)
    endif()
    # Statically link the mingw runtime (libgcc/libstdc++/winpthread) so the
    # .exe runs on a stock Windows machine with no extra DLLs to install.
    target_link_options(securevault PRIVATE -static-libgcc -static-libstdc++ -static -mwindows)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW REQUIRED glfw3)
    find_package(OpenSSL REQUIRED)
    find_package(OpenGL REQUIRED)

    target_include_directories(securevault PRIVATE ${GLFW_INCLUDE_DIRS})
    target_link_libraries(securevault PRIVATE
        ${GLFW_LIBRARIES}
        OpenSSL::Crypto
        OpenGL::GL
        dl
    )
endif()

target_compile_options(securevault PRIVATE -Wall -Wextra -Wno-unused-parameter)
