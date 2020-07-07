cmake_minimum_required(VERSION 3.0)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(nabto-client-edge-tunnel)

include_directories(include .)
add_subdirectory(nabto_cpp_wrapper)

if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/lib/windows)
elseif(UNIX AND NOT APPLE)
    link_directories(${CMAKE_SOURCE_DIR}/lib/linux)
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
target_link_libraries(edge_tunnel_client cpp_wrapper)

if(WIN32)
    install(TARGETS edge_tunnel_client RUNTIME DESTINATION .)
    install(FILES ${CMAKE_SOURCE_DIR}/lib/windows/nabto_client.dll DESTINATION .)
elseif(UNIX AND NOT APPLE)
elseif(APPLE)
endif()
