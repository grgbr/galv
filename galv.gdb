################################################################################
# SPDX-License-Identifier: GPL-3.0-only
#
# This file is part of Stroll.
# Copyright (C) 2017-2024 Grégor Boirie <gregor.boirie@free.fr>
#
# Stroll library GDB helper macro definitions.
################################################################################

define-prefix galv

document galv
Galv library macros.
Type `help galv' for more informations.
end

################################################################################
# galv_buff and galv_buff_queue macros.
################################################################################

define-prefix galv buff

define galv buff entry
stroll entry struct galv_buff node $arg0
end

document galv buff entry
Display the galv_buff entry pointed to by a struct stroll_slist_node * given by
SYM.
Usage: galv buff entry SYM
end

define galv buff queue
stroll slist entries struct galv_buff node &($arg0)->base
end

document galv buff queue
Display all galv_buff buffers linked within the galv_buff_queue pointed to by
QUEUE.
Usage: galv buff queue QUEUE
end

################################################################################
# Galv session layer macros.
################################################################################

define-prefix galv sess

document galv sess
Galv library macros related to session layer.
Type `help galv sess' for more informations.
end

define-prefix galv sess msg

define galv sess msg entry
stroll entry struct galv_sess_msg queue $arg0
end

document galv sess msg entry
Display the galv_sess_msg entry pointed to by a struct stroll_slist_node * given
by SYM.
Usage: galv sess msg SYM
end

define galv sess msg queue
stroll slist entries struct galv_sess_msg queue &($arg0)->base
end

document galv sess msg queue
Display all galv_sess_msg session messages linked within the galv_sess_msg_queue
pointed to by QUEUE.
Usage: galv sess msg queue QUEUE
end
