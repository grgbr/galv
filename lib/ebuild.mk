################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

libgalv-objects    := common.o \
                      accept.o \
                      adopt.o \
                      $(call kconf_enabled,GALV_COUPLER,coupler.o) \
                      conn.o \
                      repo.o \
                      $(call kconf_enabled,GALV_GATE,gate.o) \
                      $(call kconf_enabled,GALV_BUFF,buffer.o) \
                      $(call kconf_enabled,GALV_FRAG,fragment.o) \
                      $(call kconf_enabled,GALV_SESS,session.o) \
                      $(call kconf_enabled,GALV_UNIX,unix.o) \
                      $(call kconf_enabled,GALV_RPC,rpc.o)

solibs             := libgalv.so
libgalv.so-objs    := $(addprefix shared/,$(libgalv-objects))
libgalv.so-cflags  := $(shared-common-cflags)
libgalv.so-ldflags := $(shared-common-ldflags)
libgalv.so-pkgconf := $(common-pkgconf) libetux_timer_list

arlibs             := libgalv.a
libgalv.a-objs     := $(addprefix static/,$(libgalv-objects))
libgalv.a-cflags   := $(common-cflags)

# ex: filetype=make :
