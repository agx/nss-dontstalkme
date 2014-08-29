# This file is part of nss-dontstalkme.
#
# Copyright 2014 Guido Günther
# 
# nss-dontstalkme is free software; you can redistribute it and/or
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

include $(top_srcdir)/flymake.mk

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libnss_dontstalkme.la

AM_CPPFLAGS = -include $(top_builddir)/config.h

libnss_dontstalkme_la_SOURCES = \
	nss-dontstalkme.c

libnss_dontstalkme_la_LDFLAGS = \
	-avoid-version \
	-module \
	-export-dynamic \
	-shrext .so.2

