cmake_minimum_required(VERSION 4.2)
project(E2EMes)

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS asio system)
find_package(nlohmann_json 3.12.0 REQUIRED)
find_package(redis++ REQUIRED)
find_package(hiredis REQUIRED)
find_package(leveldb CONFIG REQUIRED)
find_package(SQLite3 REQUIRED)



find_package(Qt6 REQUIRED COMPONENTS Widgets Gui Core)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_executable(server
        server/server_main.cpp
        cryption.cpp
        cryption.h
        server/connections.cpp
        server/connections.h)

target_link_libraries(server PRIVATE
        Boost::asio
        Boost::system
        unofficial-sodium::sodium
        nlohmann_json::nlohmann_json
        redis++::redis++
        hiredis::hiredis
        SQLite::SQLite3
)

add_executable(client WIN32
        client/client_main.cpp
        cryption.cpp
        cryption.h
        client/client_activity.cpp
        client/client_activity.h
        client/client_connection.cpp
        client/client_connection.h
        client/bip_39.h

        UI/mainwindow.cpp
        UI/mainwindow.h
        UI/mainwindow.ui
)

target_link_libraries(client PRIVATE
        Qt6::Widgets
        Qt6::Gui
        Qt6::Core


        Boost::asio
        Boost::system
        unofficial-sodium::sodium
        nlohmann_json::nlohmann_json
        SQLite::SQLite3
)

target_include_directories(client PRIVATE UI)