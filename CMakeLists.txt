cmake_minimum_required(VERSION 3.0)
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
    link_directories(${CMAKE_SOURCE_DIR}/lib/windows)
elseif(UNIX AND NOT APPLE)
    add_library(nabto_client SHARED IMPORTED)
    set_target_properties( nabto_client PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/linux/libnabto_client.so)
    #link_directories(${CMAKE_SOURCE_DIR}/lib/linux)
    #set(CMAKE_SKIP_BUILD_RPATH FALSE)
    #set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH $ORIGIN)
elseif(APPLE)
    link_directories(${CMAKE_SOURCE_DIR}/lib/macos)
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
    install(FILES ${CMAKE_SOURCE_DIR}/lib/windows/nabto_client.dll DESTINATION .)
elseif(UNIX AND NOT APPLE)
    install(FILES ${CMAKE_SOURCE_DIR}/lib/linux/libnabto_client.so DESTINATION .)
elseif(APPLE)
    add_custom_command(TARGET edge_tunnel_client POST_BUILD COMMAND
                       ${CMAKE_INSTALL_NAME_TOOL} -change
                       @rpath/libnabto_client.dylib
                       @executable_path/libnabto_client.dylib
                       $<TARGET_FILE:edge_tunnel_client>)
    install(FILES ${CMAKE_SOURCE_DIR}/lib/macos/libnabto_client.dylib DESTINATION .)
endif()
