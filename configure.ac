#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([libwebsock], [1.0.1], [payden@paydensutherland.com])
AM_INIT_AUTOMAKE
LT_INIT([disable-static])
AC_CONFIG_SRCDIR([websock.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([netdb.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset socket strstr])
AC_CHECK_LIB(ssl, SSL_CTX_new, [], [
					   echo "This library requires ssl"
					   exit -1
					   ])
AC_CHECK_LIB(event, event_base_dispatch, [], [
						echo "libevent required, failing"
						exit -1
						])
AC_CHECK_LIB(event_openssl, bufferevent_openssl_socket_new, [], [
						echo "libevent_openssl required, failing"
						exit -1
						])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
