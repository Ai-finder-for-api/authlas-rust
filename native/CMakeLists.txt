cmake_minimum_required(VERSION 3.20)
project(authlas_native CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

# OpenSSL is the TLS provider for the transport. On Windows with vcpkg: -DCMAKE_PREFIX_PATH=<vcpkg>/installed/x64-windows
find_package(OpenSSL 3.0 REQUIRED)

add_library(authlas_net SHARED
  src/capi.cpp
  src/net/addr.cpp
  src/net/http_parse.cpp
  src/net/transport.cpp)
target_include_directories(authlas_net PRIVATE include src)
target_compile_definitions(authlas_net PRIVATE AUTHLAS_NET_BUILD)
target_link_libraries(authlas_net PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(authlas_net PRIVATE ws2_32 crypt32)
  target_compile_options(authlas_net PRIVATE /W4 /permissive- /utf-8 /guard:cf)
  target_link_options(authlas_net PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT)
else()
  target_compile_options(authlas_net PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2)
  set_target_properties(authlas_net PROPERTIES CXX_VISIBILITY_PRESET hidden)
endif()

# Unit tests that need no network: the parser, addresses, URLs, headers.
add_executable(net_tests tests/net_tests.cpp src/net/addr.cpp src/net/http_parse.cpp)
target_include_directories(net_tests PRIVATE src include)
if(WIN32)
  target_compile_options(net_tests PRIVATE /W4 /permissive- /utf-8)
endif()

# End-to-end TLS tests against a local server started by the test itself.
add_executable(net_tls_tests tests/net_tls_tests.cpp src/net/addr.cpp src/net/http_parse.cpp src/net/transport.cpp)
target_include_directories(net_tls_tests PRIVATE src include)
target_link_libraries(net_tls_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(net_tls_tests PRIVATE ws2_32 crypt32)
  target_compile_options(net_tls_tests PRIVATE /W4 /permissive- /utf-8)
endif()

enable_testing()
add_test(NAME net_tests COMMAND net_tests)
add_test(NAME net_tls_tests COMMAND net_tls_tests)
