################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

libgalv-clnt-cflags          := -iquote $(TOPDIR) $(common-cflags)
libgalv-clnt-ldflags         := $(common-ldflags)
libgalv-shared-clnt-cflags   := -iquote $(TOPDIR) $(shared-common-cflags)
libgalv-shared-clnt-ldflags  := $(shared-common-ldflags)

#
# Synchronous client libraries.
#

libgalv-sync-clnt-objects    := $(call kconf_enabled,GALV_RPC,rpc_clnt.o)

solibs                       := libgalv_sync_clnt.so
libgalv_sync_clnt.so-objs    := $(addprefix shared/, \
                                            $(libgalv-sync-clnt-objects))
libgalv_sync_clnt.so-cflags  := $(libgalv-shared-clnt-cflags)
libgalv_sync_clnt.so-ldflags := $(libgalv-shared-clnt-ldflags)
libgalv_sync_clnt.so-pkgconf := $(common-pkgconf)

arlibs                       := libgalv_sync_clnt.a
libgalv_sync_clnt.a-objs     := $(addprefix static/, \
                                            $(libgalv-sync-clnt-objects))
libgalv_sync_clnt.a-cflags   := $(libgalv-clnt-cflags)

#
# Asynchronous client libraries.
#

libgalv-async-clnt-objects   := client.o \
                                coupler.o \
                                $(call kconf_enabled,GALV_UNIX,unix.o)

solibs                       += libgalv_async_clnt.so
libgalv_async_clnt.so-objs   := $(addprefix shared/, \
                                            $(libgalv-async-clnt-objects))

arlibs                       += libgalv_async_clnt.a
libgalv_async_clnt.a-objs    := $(addprefix static/, \
                                          $(libgalv-async-clnt-objects))

# ex: filetype=make :
