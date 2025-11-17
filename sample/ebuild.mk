################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

smpl-ldflags := \
	$(common-ldflags) \
	-Wl,-whole-archive $(BUILDDIR)/builtin_smpl.a -Wl,-no-whole-archive \
	-Wl,-z,start-stop-visibility=hidden \
	-lgalv

builtins               := builtin_smpl.a
builtin_smpl.a-objs    := common.o
builtin_smpl.a-cflags  := $(common-cflags)

bins                   := $(call kconf_enabled,GALV_SMPL_SESS,galv-smpl-sess)
galv-smpl-sess-objs    := $(call kconf_enabled,GALV_SMPL_SESS,sess_srv.o)
galv-smpl-sess-cflags  := $(common-cflags)
galv-smpl-sess-ldflags := $(smpl-ldflags)
galv-smpl-sess-pkgconf := libelog libutils

bins                       := $(call kconf_enabled,GALV_SMPL_DISC_SRV, \
                                                   galv-smpl-disc-srv)
galv-smpl-disc-srv-objs    := $(call kconf_enabled,GALV_SMPL_DISC_SRV, \
                                                   disc_srv.o)
galv-smpl-disc-srv-cflags  := $(common-cflags)
galv-smpl-disc-srv-ldflags := $(smpl-ldflags)
galv-smpl-disc-srv-pkgconf := libelog libutils

# ex: filetype=make :
