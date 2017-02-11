#! /bin/sh
case `uname` in Darwin*) glibtoolize --copy ;;
  *) libtoolize --copy ;; esac
libtoolize
aclocal \
&& automake --add-missing \
&& autoconf
