# Generated from src.pro.

add_subdirectory(httpserver)
if(QT_FEATURE_ssl)
    add_subdirectory(sslserver)
endif()
