LIBWEBSOCK_LIBRARY_VERSION=1:0:0
lib_LTLIBRARIES=libwebsock.la
libwebsock_la_SOURCES = websock.c base64.c sha1.c frames.c default_callbacks.c api.c
libwebsock_la_LDFLAGS = -version-info $(LIBWEBSOCK_LIBRARY_VERSION)
library_includedir=$(includedir)/websock
library_include_HEADERS = websock.h
ACLOCAL_AMFLAGS = -I m4
