cmake_minimum_required(VERSION 3.7)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(qthttpserver)

find_package(Qt5 COMPONENTS Core Network REQUIRED)

add_library(${PROJECT_NAME} STATIC
    src/3rdparty/http-parser/http_parser.h
    src/3rdparty/http-parser/http_parser.c

    src/httpserver/qthttpserverglobal.h
    src/httpserver/qabstracthttpserver.h
    src/httpserver/qabstracthttpserver_p.h
    src/httpserver/qhttpserver.h
    src/httpserver/qhttpserver_p.h
    src/httpserver/qhttpserverrequest.h
    src/httpserver/qhttpserverrequest_p.h
    src/httpserver/qhttpserverresponder.h
    src/httpserver/qhttpserverresponder_p.h
    src/httpserver/qhttpserverresponse.h
    src/httpserver/qhttpserverresponse_p.h
    src/httpserver/qhttpserverrouter.h
    src/httpserver/qhttpserverrouter_p.h
    src/httpserver/qhttpserverrouterrule.h
    src/httpserver/qhttpserverrouterrule_p.h
    src/httpserver/qhttpserverrouterviewtraits.h

    src/httpserver/qabstracthttpserver.cpp
    src/httpserver/qhttpserver.cpp
    src/httpserver/qhttpserverrequest.cpp
    src/httpserver/qhttpserverresponder.cpp
    src/httpserver/qhttpserverresponse.cpp
    src/httpserver/qhttpserverrouter.cpp
    src/httpserver/qhttpserverrouterrule.cpp
)
target_link_libraries(${PROJECT_NAME} PUBLIC Qt5::Core Qt5::Network)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_BINARY_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE
    ${Qt5Core_PRIVATE_INCLUDE_DIRS}
    ${Qt5Network_PRIVATE_INCLUDE_DIRS}
    src/3rdparty/http-parser
)
add_library(Qt5::HttpServer ALIAS ${PROJECT_NAME})

# emulate qt folders
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${PROJECT_SOURCE_DIR}/src/httpserver ${PROJECT_BINARY_DIR}/QtHttpServer)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${PROJECT_SOURCE_DIR}/src/httpserver ${PROJECT_BINARY_DIR}/private)

add_subdirectory(tests)
