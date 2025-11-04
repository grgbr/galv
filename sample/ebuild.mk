################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Galv.
# Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

include ../common.mk

bins                   := $(call kconf_enabled,GALV_SMPL_SESS,galv-smpl-sess)
galv-smpl-sess-objs    += $(call kconf_enabled,GALV_SMPL_SESS,sess_srv.o)
galv-smpl-sess-cflags  := $(common-cflags)
galv-smpl-sess-ldflags := $(common-ldflags) -lgalv
galv-smpl-sess-pkgconf := libelog libutils

# ex: filetype=make :
