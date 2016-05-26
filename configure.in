dnl Process this file with autoconf to produce a configure script.
AC_INIT(statusq.c)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

dnl Checks for libraries.
AC_CHECK_LIB(xnet, socket)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(resolv, inet_aton)

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(stdint.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_TYPE(uint8_t, [AC_DEFINE(my_uint8_t, uint8_t)], [AC_CHECK_TYPE(u_int8_t, [AC_DEFINE(my_uint8_t, u_int8_t)])])
AC_CHECK_TYPE(uint16_t, [AC_DEFINE(my_uint16_t, uint16_t)], [AC_CHECK_TYPE(u_int16_t, [AC_DEFINE(my_uint16_t, u_int16_t)])])
AC_CHECK_TYPE(uint32_t, [AC_DEFINE(my_uint32_t, uint32_t)], [AC_CHECK_TYPE(u_int32_t, [AC_DEFINE(my_uint32_t, u_int32_t)])])


AC_C_CONST
AC_HEADER_TIME

dnl Checks for library functions.
AC_CHECK_FUNCS(snprintf inet_aton socket)

AC_CANONICAL_SYSTEM

if test "$target_os" = cygwin; then
AC_DEFINE(WINDOWS)
BINDIR=c:
TARGET=nbtscan.exe
else
AC_DEFINE(UNIX)
BINDIR=$prefix/bin
TARGET=nbtscan
fi

AC_SUBST(TARGET)
AC_SUBST(BINDIR)

AC_OUTPUT(Makefile)
