cmake_minimum_required(VERSION 4.2)
project(E2EMes)

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS asio system)
find_package(nlohmann_json 3.12.0 REQUIRED)
find_package(redis++ REQUIRED)
find_package(hiredis REQUIRED)

set(CMAKE_CXX_STANDARD 20)

add_executable(server
        server_main.cpp
        cryption.cpp
        cryption.h
        connections.cpp
        connections.h)

target_link_libraries(server PRIVATE
        Boost::asio
        Boost::system
        unofficial-sodium::sodium
        nlohmann_json::nlohmann_json
        redis++::redis++
        hiredis::hiredis
)

add_executable(client
        client_main.cpp
        cryption.cpp
        cryption.h)

target_link_libraries(client PRIVATE
        Boost::asio
        Boost::system
        unofficial-sodium::sodium
        nlohmann_json::nlohmann_json
)