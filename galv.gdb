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

define galv buff print
set $_galv_buff = (struct galv_buff *)($arg0)
if $_galv_buff->node.next != 0
	set $_galv_buff_off = (unsigned long)(&((struct galv_buff *)0)->node)
	set $_galv_buff_next = (struct galv_buff *) \
	                       ((const char *)(($_galv_buff)->node.next) - \
	                        $_galv_buff_off)
else
	set $_galv_buff_next = (struct galv_buff *)0x0
end
if $argc == 2
	set $_galv_buff_indent = $arg1
else
	set $_galv_buff_indent = ""
end
output $_galv_buff
printf ":\n%shead: %-5hu                 busy:  %u", \
	$_galv_buff_indent, \
	($_galv_buff)->base.head_off, \
	($_galv_buff)->base.busy_len
printf "\n%scapa: %-5hu                 ref:   %u", \
	$_galv_buff_indent, \
	($_galv_buff)->base.capacity, \
	($_galv_buff)->ref
printf "\n%smem:  (uint8_t *)           alloc: (struct stroll_falloc *)", \
$_galv_buff_indent
printf "\n%s      %-18p           %-p", \
	$_galv_buff_indent, \
	($_galv_buff)->mem, \
	($_galv_buff)->alloc
printf "\n%snext: (struct galv_buff *)  queue: (struct galv_buff_queue *)", \
	$_galv_buff_indent
printf "\n%s      %-18p           %-p\n", \
	$_galv_buff_indent, \
	$_galv_buff_next, \
	($_galv_buff)->queue
end

document galv buff print
Display the galv_buff buffer pointed to by BUFFER
Usage: galv buff print BUFFER
end

define galv buff dump
set $_galv_buff = (struct galv_buff *)($arg0)
eval "x/%zub &($_galv_buff)->mem[$_galv_buff->base.head_off]", \
     ($_galv_buff)->base.busy_len
end

document galv buff dump
Show a memory dump of `busy' content available into the galv_buff buffer pointed
to by BUFFER.
Usage: galv buff dump BUFFER
end

define galv buff entry
set $_galv_buff_off = (unsigned long)(&((struct galv_buff *)0)->node)
set $_galv_buff = (struct galv_buff *)((const char *)($arg0) - $_galv_buff_off)
if $argc == 2
	set $_galv_buff_indent = $arg1
else
	set $_galv_buff_indent = ""
end
galv buff print $_galv_buff $_galv_buff_indent
end

document galv buff entry
Display the galv_buff entry pointed to by a struct stroll_slist_node * given by
NODE.
Usage: galv buff entry NODE
end

define galv buff queue
set $_galv_buff_node = ((struct galv_buff_queue *)($arg0))->base.head.next
set $_galv_buff_idx = 0
while $_galv_buff_node
	printf "[%10u] ", $_galv_buff_idx
	galv buff entry $_galv_buff_node "             "

	set $_galv_buff_node = $_galv_buff_node->next
	set $_galv_buff_idx = $_galv_buff_idx + 1
end
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
set $_galv_frag = (struct galv_frag *)($arg0)
if $_galv_frag->list.next != 0
	set $_galv_frag_off = (unsigned long)(&((struct galv_frag *)0)->list)
	set $_galv_frag_next = (struct galv_frag *)
	             ((const char *)(($_galv_frag)->list.next) - $_galv_frag_off)
else
	set $_galv_frag_next = (struct galv_frag *)0x0
end
if $argc == 2
	set $_galv_frag_indent = $arg1
else
	set $_galv_frag_indent = ""
end
output $_galv_frag
printf ":\n%shead: %-5hu                 busy: %u", \
	$_galv_frag_indent, \
	($_galv_frag)->base.head_off, \
	($_galv_frag)->base.busy_len
printf "\n%scapa: %hu", $_galv_frag_indent, ($_galv_frag)->base.capacity
printf "\n%sbuff: (struct galv_buff *)  next: (struct galv_frag *)", \
$_galv_frag_indent
printf "\n%s      %-18p          %-p\n", \
	$_galv_frag_indent, \
	($_galv_frag)->buff, \
	$_galv_frag_next
end

document galv frag print
Display the galv_frag fragment pointed to by FRAGMENT.
Usage: galv frag print FRAGMENT
end

define galv frag dump
set $_galv_frag = (struct galv_frag *)($arg0)
eval "x/%zub &($_galv_frag)->buff->mem[$_galv_frag->base.head_off]", \
     ($_galv_frag)->base.busy_len
end

document galv frag dump
Show a memory dump of `busy' content available into the galv_frag fragment
pointed to by FRAGMENT.
Usage: galv frag dump FRAGMENT
end

define galv frag entry
set $_galv_frag_off = (unsigned long)(&((struct galv_frag *)0)->list)
set $_galv_frag = (struct galv_frag *)((const char *)($arg0) - $_galv_frag_off)
if $argc == 2
	set $_galv_frag_indent = $arg1
else
	set $_galv_frag_indent = ""
end
galv frag print $_galv_frag $_galv_frag_indent
end

document galv frag entry
Display the galv_frag entry pointed to by a struct stroll_slist_node * given by
NODE.
Usage: galv frag entry NODE
end

define galv frag list
set $_galv_frag_node = ((struct galv_frag_list *)($arg0))->base.head.next
set $_galv_frag_idx = 0
if $argc == 2
	set $_galv_frag_list_indent = $arg1
else
	set $_galv_frag_list_indent = ""
end
eval "set $_galv_frag_list_entry_indent = \"%s             \"", \
	$_galv_frag_list_indent
while $_galv_frag_node
	printf "%s[%10u] ", $_galv_frag_list_indent, $_galv_frag_idx
	galv frag entry $_galv_frag_node $_galv_frag_list_entry_indent

	set $_galv_frag_node = $_galv_frag_node->next
	set $_galv_frag_idx = $_galv_frag_idx + 1
end
end

document galv frag list
Display all galv_frag fragments linked within the galv_frag_list pointed to by
LIST.
Usage: galv frag list LIST
end

# Displays ordered list of fragments as pointers to struct galv_frag.
# For internal usage only.
define _galv_frag_list
set $_galv_frag_list = (struct galv_frag_list *)($arg0)
set $_galv_frag_off = (unsigned long)(&((struct galv_frag *)0)->list)
set $_galv_frag_node = ($_galv_frag_list)->base.head.next
if $argc == 2
	set $_galv_frag_indent = $arg1
else
	set $_galv_frag_indent = ""
end
set $_galv_frag_idx = 0
if $_galv_frag_node
	set $_galv_frag = (struct galv_frag *) \
	                  ((const char *)($_galv_frag_node) - $_galv_frag_off)
	printf "\n%s[%10u] ", $_galv_frag_indent, $_galv_frag_idx
	output $_galv_frag
	set $_galv_frag_node = $_galv_frag_node->next
	set $_galv_frag_idx = $_galv_frag_idx + 1
end
while $_galv_frag_node
	set $_galv_frag = (struct galv_frag *) \
	                  ((const char *)($_galv_frag_node) - $_galv_frag_off)
	printf ",\n%s%10u: ", $_galv_frag_indent, $_galv_frag_idx
	output $_galv_frag

	set $_galv_frag_node = $_galv_frag_node->next
	set $_galv_frag_idx = $_galv_frag_idx + 1
end
end

# For internal usage only.
define _galv_frag_dump_list
set $_galv_frag_list = (struct galv_frag_list *)($arg0)
set $_galv_frag_off = (unsigned long)(&((struct galv_frag *)0)->list)
set $_galv_frag_node = ($_galv_frag_list)->base.head.next
if $argc == 2
	set $_galv_frag_indent = $arg1
else
	set $_galv_frag_indent = ""
end
set $_galv_frag_idx = 0
while $_galv_frag_node
	set $_galv_frag = (struct galv_frag *) \
	                  ((const char *)($_galv_frag_node) - $_galv_frag_off)
	printf "%s[%10u] ", $_galv_frag_indent, $_galv_frag_idx
	output $_galv_frag
	printf ":\n"
	galv frag dump $_galv_frag

	set $_galv_frag_node = $_galv_frag_node->next
	set $_galv_frag_idx = $_galv_frag_idx + 1
end
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
set $_galv_sessmsg = (struct galv_sess_msg *)($arg0)
if $_galv_sessmsg->recv.queue.next != 0
	set $_galv_sessmsg_off = (unsigned long) \
                                 (&((struct galv_sess_msg *)0)->recv.queue)
	set $_galv_sessmsg_next = (struct galv_sess_msg *) \
	                          ((const char *) \
	                           (($_galv_sessmsg)->recv.queue.next) - \
	                           $_galv_sessmsg_off)
else
	set $_galv_sessmsg_next = (struct galv_sess_msg *)0x0
end
if $argc == 2
	set $_galv_sessmsg_indent = $arg1
else
	set $_galv_sessmsg_indent = ""
end
set $_galv_sessmsg_type = ($_galv_sessmsg)->type
if $_galv_sessmsg_type == GALV_SESS_HEAD_REQUEST_TYPE
	set $_galv_sessmsg_type_str = "request"
else
	if $_galv_sessmsg_type == GALV_SESS_HEAD_REPLY_TYPE
		set $_galv_sessmsg_type_str = "reply  "
	else
		if $_galv_sessmsg_type == GALV_SESS_HEAD_NOTIF_TYPE
			set $_galv_sessmsg_type_str = "notif  "
		else
			set $_galv_sessmsg_type_str = "?      "
		end
	end
end
eval "set $_galv_sessmsg_frag_indent = \"%s           \"", $_galv_sessmsg_indent
output $_galv_sessmsg
printf ":\n%stype: %s                  xchg: %u", \
	$_galv_sessmsg_indent, \
	$_galv_sessmsg_type_str, \
	($_galv_sessmsg)->xchg
printf "\n%ssize: %u", \
	$_galv_sessmsg_indent, \
	($_galv_sessmsg)->size
printf "\n%snext: (struct galv_sess_msg *) %p", \
	$_galv_sessmsg_indent, \
	$_galv_sessmsg_next
printf "\n%sfragments: (struct galv_frag_list *) %p:\n", \
	$_galv_sessmsg_indent, \
	&($_galv_sessmsg)->recv.frags
galv frag list &($_galv_sessmsg)->recv.frags $_galv_sessmsg_frag_indent
end

document galv sessmsg print
Display the galv_sess_msg message pointed to by MESSAGE.
Usage: galv sessmsg print MESSAGE
end

define galv sessmsg dump
set $_galv_sessmsg = (struct galv_sess_msg *)($arg0)
_galv_frag_dump_list &$_galv_sessmsg->recv.frags
end

document galv sessmsg dump
Show a memory dump of `busy' content available into the galv_sess_msg session
message pointed to by MESSAGE.
Usage: galv sessmsg dump MESSAGE
end

define galv sessmsg entry
set $_galv_sessmsg_off = (unsigned long) \
                         (&((struct galv_sess_msg *)0)->recv.queue)
set $_galv_sessmsg = (struct galv_sess_msg *)((const char *)($arg0) - \
                                              $_galv_sessmsg_off)
if $argc == 2
	set $_galv_sessmsg_indent = $arg1
else
	set $_galv_sessmsg_indent = ""
end
galv sessmsg print $_galv_sessmsg $_galv_sessmsg_indent
end

document galv sessmsg entry
Display the galv_sess_msg entry pointed to by a struct stroll_slist_node * given
by NODE.
Usage: galv sessmsg entry NODE
end

define galv sessmsg queue
set $_galv_sessmsg_node = ((struct stroll_slist_node *)($arg0))->head.next
set $_galv_sessmsg_idx = 0
while $_galv_sessmsg_node
	printf "[%10u] ", $_galv_sessmsg_idx
	galv sessmsg entry $_galv_sessmsg_node "             "

	set $_galv_sessmsg_node = $_galv_sessmsg_node->next
	set $_galv_sessmsg_idx = $_galv_sessmsg_idx + 1
end
end

document galv sessmsg queue
Display all galv_sess_msg messages linked within the stroll_slist
session message queue pointed to by QUEUE.
Usage: galv sessmsg queue QUEUE
end
