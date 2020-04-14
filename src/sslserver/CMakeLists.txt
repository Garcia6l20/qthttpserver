# Generated from sslserver.pro.

#####################################################################
## SslServer Module:
#####################################################################

add_qt_module(SslServer
    SOURCES
        qsslserver.cpp qsslserver.h qsslserver_p.h
        qtsslserverglobal.h
    INCLUDE_DIRECTORIES
        .
    LIBRARIES
        Qt::CorePrivate
        Qt::NetworkPrivate
    PUBLIC_LIBRARIES
        Qt::Core
        Qt::Network
    PRIVATE_MODULE_INTERFACE
        Qt::CorePrivate
        Qt::NetworkPrivate
)
