cmake_minimum_required(VERSION 3.0)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(nabto-client-edge-tunnel)

find_package(Threads)

include_directories(include .)
add_subdirectory(nabto_cpp_wrapper)

if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/lib/windows)
elseif(UNIX AND NOT APPLE)
    link_directories(${CMAKE_SOURCE_DIR}/lib/linux)
    set(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH $ORIGIN)
elseif(APPLE)
    link_directories(${CMAKE_SOURCE_DIR}/lib/macos)
endif()

set(src
    src/edge_tunnel.cpp
    src/json_config.cpp
    src/pairing.cpp
    src/timestamp.cpp
)

add_executable(edge_tunnel_client ${src})
target_link_libraries(edge_tunnel_client cpp_wrapper ${CMAKE_THREAD_LIBS_INIT})

if(WIN32)
    install(TARGETS edge_tunnel_client RUNTIME DESTINATION .)
    install(FILES ${CMAKE_SOURCE_DIR}/lib/windows/nabto_client.dll DESTINATION .)
elseif(UNIX AND NOT APPLE)
    install(TARGETS edge_tunnel_client RUNTIME DESTINATION .
            PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(FILES ${CMAKE_SOURCE_DIR}/lib/linux/libnabto_client.so DESTINATION .)
elseif(APPLE)
endif()
