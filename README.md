# libwebsock

C library for easy WebSockets servers.

This library allows a developer to quickly develop WebSocket servers by focusing
on the actual logic of your WebSocket implementation instead of the details
of the WebSocket protocol or even specifics of C sockets.

Installation instructions can be found [here][6].

API reference & usage instructions can be found [here][7].

To get started, have a look at [echo.c][1] in the examples directory of the package.  A
simple echo server is implemented.

You can find the latest autobahn test results [here][3].

Current Travis CI Build Status:

[![Build Status][4]][5]

## Features

* Callbacks for events
* SSL Support
* Easy to use
* Uses [libevent][2] for portability (tested on Linux/FreeBSD)
* IPv6 support
* No failures on Autobahn Test suite

## Compiling

### Unix

Using the autotools project:

```bash
$ sudo apt-get install autotools-dev automake libevent-dev
$ ./autogen.sh
$ ./configure
$ make
```

Using [CMake][8]:

```bash
$ mkdir build && cd build
$ cmake ..
$ make
```

### Windows

To compile on Windows using CMake, do the following in *git bash*:

```bash
#
# Or place this wherever you want to build...
#
$ cd /c
$ mkdir dev && cd dev

#
# Download latest OpenSSL Win32 binary: http://slproweb.com/products/Win32OpenSSL.html
#
$ curl -O http://slproweb.com/download/Win32OpenSSL-1_0_1L.exe
$ /c/Windows/System32/cmd.exe
$ Win32OpenSSL-1_0_1L.exe /silent /verysilent /sp- /suppressmsgboxes
$ exit

#
# Build Libevent
#
$ git clone git@github.com:nmathewson/Libevent.git
$ cd Libevent
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
$ cd ../..

#
# Get Win32 pthreads.
#
$ curl -O ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.zip
$ unzip -d pthreads-win32 pthreads-w32-2-9-1-release.zip

#
# Build libwebsock
#
$ git clone git@github.com:payden/libwebsock.git
$ cd libwebsock
$ mkdir build && cd build
$ cmake -DPTHREADS_WIN32_DIR=/c/dev/pthreads-win32/Pre-built.2/ -DLIBEVENT_DIR=/c/dev/Libevent/build ..
$ start libwebsock.sln  # Use Visual Studio GUI to build.
$ cmake --build .       # Or build via command line.
```

 [1]: https://github.com/payden/libwebsock/blob/master/examples/echo.c
 [2]: http://libevent.org
 [3]: http://paydensutherland.com/autobahn
 [4]: https://travis-ci.org/payden/libwebsock.png
 [5]: https://travis-ci.org/payden/libwebsock
 [6]: https://github.com/payden/libwebsock/wiki/Installation
 [7]: https://github.com/payden/libwebsock/wiki/API
 [8]: http://www.cmake.org/
