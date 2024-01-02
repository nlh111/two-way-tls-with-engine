cmake_minimum_required(VERSION 3.0)
project("csr-test")
include_directories("/usr/local/Cellar/openssl@3/3.1.3/include")
include_directories("/usr/local/include")
link_directories("/usr/local/Cellar/openssl@3/3.1.3/lib")
link_directories("/usr/local/lib")

set(libs
    mbedtls
    mbedcrypto
    crypto
    ssl
)

add_library(tlsengine SHARED engine.c)
target_link_libraries(tlsengine PRIVATE ${libs})

add_executable(client client.c)
target_link_libraries(client PRIVATE ${libs} tlsengine)

add_executable(server server.c)
target_link_libraries(server PRIVATE ${libs})
