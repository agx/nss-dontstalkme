# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Copyright 2014 Guido Günther <agx@sigxcpu.org>
#
# nss-myhostname is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# nss-dontstalkme is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with nss-dontstalkme. If not, If not, see
# <http://www.gnu.org/licenses/>.
#
# Based on configure.ac from libnss-myhostname

AC_PREREQ(2.62)
AC_INIT([nss-dontstalkme],[0.0.1])
AC_CONFIG_SRCDIR([src/nss-dontstalkme.c])
dnl Make automake keep quiet about wildcards & other GNUmake-isms
AM_INIT_AUTOMAKE([1.11.1 no-dist-gzip dist-xz -Wno-portability])
AC_CONFIG_HEADERS([config.h])
AC_SYS_LARGEFILE

AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# libtool stuff
AC_DISABLE_STATIC
LT_PREREQ(2.2)
LT_INIT

# GCC flags
DESIRED_FLAGS="-Wall -W -Wextra -pedantic -pipe -Wformat -Wold-style-definition -Wdeclaration-after-statement -Wfloat-equal -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wpointer-arith -Wcast-align -Wwrite-strings -Winline -Wno-unused-parameter -ffast-math -fvisibility=hidden -fdiagnostics-show-option"

for flag in $DESIRED_FLAGS ; do
  CC_CHECK_CFLAGS([$flag], [CFLAGS="$CFLAGS $flag"])
done

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([nss.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
