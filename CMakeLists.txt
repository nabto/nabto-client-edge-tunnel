cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(nabto-client-edge-tunnel)

find_package(Threads)

include_directories(include .)
include_directories(include/3rdparty)

add_custom_target(GENERATE_VERSION ALL
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/src/version.cpp
  COMMAND ${CMAKE_COMMAND} -P
  ${CMAKE_CURRENT_SOURCE_DIR}/version.cmake
  )

if(WIN32)
    include(InstallRequiredSystemLibraries)

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(NABTO_CLIENT_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/windows-i386)
    else()
        set(NABTO_CLIENT_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/windows-x86_64)
    endif()
    link_directories(${NABTO_CLIENT_LIB_DIR})
elseif(UNIX AND NOT APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(NABTO_CLIENT_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/linux-aarch64)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
        set(NABTO_CLIENT_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/linux-armhf)
    else()
        set(NABTO_CLIENT_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/linux-x86_64)
    endif()
    add_library(nabto_client SHARED IMPORTED)
    set_target_properties(nabto_client PROPERTIES IMPORTED_LOCATION ${NABTO_CLIENT_LIB_DIR}/libnabto_client.so)
    set(CMAKE_INSTALL_RPATH $ORIGIN)
elseif(APPLE)
    set(NABTO_CLIENT_LIB_DIR ${CMAKE_SOURCE_DIR}/lib/macos-universal)
    link_directories(${NABTO_CLIENT_LIB_DIR})
endif()

add_subdirectory(nabto_cpp_wrapper)

set(src
    src/edge_tunnel.cpp
    src/config.cpp
    src/pairing.cpp
    src/timestamp.cpp
    src/iam.cpp
    src/iam_interactive.cpp
    src/version.cpp
)

add_executable(edge_tunnel_client ${platform_src} ${src})
target_link_libraries(edge_tunnel_client cpp_wrapper ${CMAKE_THREAD_LIBS_INIT})

add_dependencies(edge_tunnel_client GENERATE_VERSION)

install(TARGETS edge_tunnel_client RUNTIME DESTINATION .
        PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
if(WIN32)
    install(FILES ${NABTO_CLIENT_LIB_DIR}/nabto_client.dll DESTINATION .)
    install(FILES ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS} DESTINATION . COMPONENT Libraries)
elseif(UNIX AND NOT APPLE)
    install(FILES ${NABTO_CLIENT_LIB_DIR}/libnabto_client.so DESTINATION .)
elseif(APPLE)
    add_custom_command(TARGET edge_tunnel_client POST_BUILD COMMAND
                       ${CMAKE_INSTALL_NAME_TOOL} -change
                       @rpath/libnabto_client.dylib
                       @executable_path/libnabto_client.dylib
                       $<TARGET_FILE:edge_tunnel_client>)
    install(FILES ${NABTO_CLIENT_LIB_DIR}/libnabto_client.dylib DESTINATION .)
endif()
