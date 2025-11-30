#!/bin/sh -e

send()
{
	local xchg=$1
	local sz=$(($2 - 1))
	local szh
	local szl

	xchg=$(printf "%02x" $xchg)
	szh=$(printf "%02x" $((sz>>8)))
	szl=$(printf "%02x" $((sz&0xff)))

	/bin/echo -en "\x01\x$xchg\x$szl\x$szh"
	dd if=/dev/zero bs=$((sz + 1)) count=1 2>/dev/null
}

send_mult()
{
	local sz=$1
	local nr=$2
	local xchg=0

	while [ $xchg -lt $nr ]; do
		send "$xchg" "$sz"
		xchg=$((xchg + 1))
	done | nc -U -N ./sock
}

#send_mult 1 256

#send_mult 4088 256
#send_mult 4089 256
#send_mult 4090 256
#send_mult 4091 256
#send_mult 4092 256
send_mult 4093 256
#send_mult 4094 256
#send_mult 4095 256
#send_mult 4096 256
