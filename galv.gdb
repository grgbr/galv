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
# galv_frag and galv_frag_list macros.
################################################################################

define-prefix galv frag

define galv frag print
set $_frag = (struct galv_frag *)($arg0)
if $_frag->list.next != 0
	set $_off = (unsigned long)(&((struct galv_frag *)0)->list)
	set $_next = (struct galv_frag *)
	             ((const char *)(($_frag)->list.next) - $_off)
else
	set $_next = (struct galv_frag *)0x0
end
if $argc == 2
	set $_indent = $arg1
else
	set $_indent = ""
end
printf "*"
output $_frag
printf " = {\n%s\thead = ", $_indent
output ($_frag)->base.head_off
printf ",\n%s\tbusy = ", $_indent
output ($_frag)->base.busy_len
printf ",\n%s\tcapa = ", $_indent
output ($_frag)->base.capacity
printf ",\n%s\tnext = ", $_indent
output $_next
printf ",\n%s\tbuff = ", $_indent
output ($_frag)->buff
printf "\n%s}\n", $_indent
end

document galv frag print
Display the galv_frag fragment pointed to by FRAG.
Usage: galv frag print FRAG
end

define galv frag entry
set $_off = (unsigned long)(&((struct galv_frag *)0)->list)
set $_frag = (struct galv_frag *)((const char *)($arg0) - $_off)
if $argc == 2
	set $_indent = $arg1
else
	set $_indent = ""
end
galv frag print $_frag $_indent
end

document galv frag entry
Display the galv_frag entry pointed to by a struct stroll_slist_node * given by
NODE.
Usage: galv frag entry NODE
end

define galv frag list
set $_node = ((struct galv_frag_list *)($arg0))->base.head.next
set $_idx = 0
while $_node
	printf "%10u: ", $_idx
	galv frag entry $_node "            "

	set $_node = $_node->next
	set $_idx = $_idx + 1
end
end

document galv frag list
Display all galv_frag fragments linked within the galv_frag_list pointed to by
LIST.
Usage: galv frag list LIST
end

################################################################################
# Galv session layer macros.
################################################################################

define-prefix galv sessmsg

document galv sessmsg
Galv library macros related to session layer messages.
Type `help galv sessmsg' for more informations.
end

define galv sessmsg print
set $_msg = (struct galv_sess_msg *)($arg0)
if $_msg->queue.next != 0
	set $_off = (unsigned long)(&((struct galv_sess_msg *)0)->list)
	set $_next = (struct galv_sess_msg *)
	             ((const char *)(($_frag)->queue.next) - $_off)
else
	set $_next = (struct galv_sess_msg *)0x0
end
if $argc == 2
	set $_indent = $arg1
else
	set $_indent = ""
end
printf "*"
output $_msg
printf " = {\n%s\tsize  = ", $_indent
output ($_msg)->size
printf ",\n%s\tmulti = ", $_indent
output ($_msg)->multi
printf ",\n%s\ttype  = ", $_indent
output ($_msg)->type
printf ",\n%s\txchg  = ", $_indent
output ($_msg)->xchg
printf ",\n%s\tsgmt  = ", $_indent
output ($_msg)->sgmt
printf ",\n%s\tfrags = ", $_indent
output &($_msg)->frags
printf ",\n%s\tnext  = ", $_indent
output $_next
printf "\n%s}\n", $_indent
end

document galv sessmsg print
Display the galv_sess_msg message pointed to by MSG.
Usage: galv sessmsg print MSG
end

define galv sessmsg entry
set $_off = (unsigned long)(&((struct galv_sess_msg *)0)->queue)
set $_msg = (struct galv_sess_msg *)((const char *)($arg0) - $_off)
if $argc == 2
	set $_indent = $arg1
else
	set $_indent = ""
end
galv sessmsg print $_msg $_indent
end

document galv sessmsg entry
Display the galv_sess_msg entry pointed to by a struct stroll_slist_node * given
by NODE.
Usage: galv sessmsg entry NODE
end

define galv sessmsg queue
set $_node = ((struct galv_sess_msg_queue *)($arg0))->base.head.next
set $_idx = 0
while $_node
	printf "%10u: ", $_idx
	galv sessmsg entry $_node "            "

	set $_node = $_node->next
	set $_idx = $_idx + 1
end
end

document galv sessmsg queue
Display all galv_sess_msg session messages linked within the galv_sess_msg_queue
pointed to by QUEUE.
Usage: galv sessmsg queue QUEUE
end
