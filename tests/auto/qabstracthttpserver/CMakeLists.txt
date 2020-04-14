# Generated from qabstracthttpserver.pro.

#####################################################################
## tst_qabstracthttpserver Test:
#####################################################################

qt_add_test(tst_qabstracthttpserver
    SOURCES
        tst_qabstracthttpserver.cpp
    PUBLIC_LIBRARIES
        Qt::HttpServer
)

## Scopes:
#####################################################################

qt_extend_target(tst_qabstracthttpserver CONDITION TARGET Qt::WebSockets
    PUBLIC_LIBRARIES
        Qt::WebSockets
)
