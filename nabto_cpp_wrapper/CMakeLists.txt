set(src
  nabto_client_impl.cpp
  nabto_client.cpp
  )

add_library(cpp_wrapper ${src})
target_link_libraries(cpp_wrapper nabto_client)
target_include_directories(cpp_wrapper PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
