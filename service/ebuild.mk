################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

libgalv-svc-cflags         := -iquote $(TOPDIR) $(common-cflags)
libgalv-svc-ldflags        := $(common-ldflags)
libgalv-shared-svc-cflags  := -iquote $(TOPDIR) $(shared-common-cflags)
libgalv-shared-svc-ldflags := $(shared-common-ldflags)


libgalv-svc-objects        := accept.o \
                              adopt.o \
                              $(call kconf_enabled,GALV_GATE,gate.o) \
                              $(call kconf_enabled,GALV_UNIX,unix.o) \
                              $(call kconf_enabled,GALV_SESS,session.o) \
                              $(call kconf_enabled,GALV_RPC,rpc.o)

solibs                     := libgalv_svc.so
libgalv_svc.so-objs        := $(addprefix shared/,$(libgalv-svc-objects))
libgalv_svc.so-cflags      := $(libgalv-shared-svc-cflags)
libgalv_svc.so-ldflags     := $(libgalv-shared-svc-ldflags) \
                              -lgalv_common
libgalv_svc.so-pkgconf     := $(common-pkgconf)

arlibs                     := libgalv_svc.a
libgalv_svc.a-objs         := $(addprefix static/,$(libgalv-svc-objects))
libgalv_svc.a-cflags       := $(libgalv-svc-cflags)

# ex: filetype=make :

