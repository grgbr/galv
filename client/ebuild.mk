################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

libgalv-objects         := $(call kconf_enabled,GALV_RPC,rpc_clnt.o)

solibs                  := libgalv_clnt.so
libgalv_clnt.so-objs    := $(addprefix shared/,$(libgalv-objects))
libgalv_clnt.so-cflags  := $(shared-common-cflags)
libgalv_clnt.so-ldflags := $(shared-common-ldflags)
libgalv_clnt.so-pkgconf := $(common-pkgconf)

arlibs                  := libgalv_clnt.a
libgalv_clnt.a-objs     := $(addprefix static/,$(libgalv-objects))
libgalv_clnt.a-cflags   := $(common-cflags)

# ex: filetype=make :
