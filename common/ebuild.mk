################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

libgalv-common-cflags         := -iquote $(TOPDIR) $(common-cflags)
libgalv-common-ldflags        := $(common-ldflags)
libgalv-shared-common-cflags  := -iquote $(TOPDIR) $(shared-common-cflags)
libgalv-shared-common-ldflags := $(shared-common-ldflags)

libgalv-common-objects        := common.o \
                                 timer.o \
                                 conn.o \
                                 repo.o \
                                 $(call kconf_enabled,GALV_BUFF,buffer.o) \
                                 $(call kconf_enabled,GALV_FRAG,fragment.o) \
                                 $(call kconf_enabled,GALV_UNIX,unix.o)

solibs                        := libgalv_common.so
libgalv_common.so-objs        := $(addprefix shared/,$(libgalv-common-objects))
libgalv_common.so-cflags      := $(libgalv-shared-common-cflags)
libgalv_common.so-ldflags     := $(libgalv-shared-common-ldflags)
libgalv_common.so-pkgconf     := $(common-pkgconf) $(timer-pkgconf)

arlibs                        := libgalv_common.a
libgalv_common.a-objs         := $(addprefix static/,$(libgalv-common-objects))
libgalv_common.a-cflags       := $(libgalv-common-cflags)

# ex: filetype=make :
