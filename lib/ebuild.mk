################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

libgalv-objects    := common.o \
                      $(call kconf_enabled,GALV_UNIX_CONN,conn.o) \
                      $(call kconf_enabled,GALV_UNIX_CONN,acceptor.o) \
                      $(call kconf_enabled,GALV_FABRIC,fabric.o) \
                      $(call kconf_enabled,GALV_REPO,repo.o) \
                      $(call kconf_enabled,GALV_UNIX_CONN,unix.o) \
                      $(call kconf_enabled,GALV_SESS,session.o)

solibs             := libgalv.so
libgalv.so-objs    := $(addprefix shared/,$(libgalv-objects))
libgalv.so-cflags  := $(shared-common-cflags)
libgalv.so-ldflags := $(shared-common-ldflags)
libgalv.so-pkgconf := $(common-pkgconf)

arlibs             := libgalv.a
libgalv.a-objs     := $(addprefix static/,$(libgalv-objects))
libgalv.a-cflags   := $(common-cflags)

# ex: filetype=make :
