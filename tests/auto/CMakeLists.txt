find_package(Qt5 COMPONENTS Test REQUIRED)

# auto link subfolders to Qt5::Test and Qt5::HttpServer
link_libraries(Qt5::Test Qt5::HttpServer)

add_subdirectory(qabstracthttpserver)
add_subdirectory(qhttpserver)
add_subdirectory(qhttpserverresponder)
add_subdirectory(qhttpserverresponse)
add_subdirectory(qhttpserverrouter)
