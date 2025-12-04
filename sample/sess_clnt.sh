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
	sync
}

send_mult 1 256
send_mult 2 256
send_mult 3 256
send_mult 4 256
send_mult 5 256
send_mult 6 256
send_mult 7 256
send_mult 8 256
send_mult 9 256
send_mult 10 256
send_mult 11 256
send_mult 12 256

send_mult 12 256
send_mult 13 256
send_mult 14 256
send_mult 15 256
send_mult 16 256
send_mult 17 256

send_mult 28 256
send_mult 29 256
send_mult 30 256
send_mult 31 256
send_mult 32 256
send_mult 33 256

send_mult 124 256
send_mult 125 256
send_mult 126 256
send_mult 127 256
send_mult 128 256
send_mult 129 256

send_mult 252 256
send_mult 253 256
send_mult 254 256
send_mult 255 256
send_mult 256 256
send_mult 257 256

send_mult 252 256
send_mult 253 256
send_mult 254 256
send_mult 255 256
send_mult 256 256
send_mult 257 256

send_mult 508 256
send_mult 509 256
send_mult 510 256
send_mult 511 256
send_mult 512 256
send_mult 513 256

send_mult 1020 256
send_mult 1021 256
send_mult 1022 256
send_mult 1023 256
send_mult 1024 256
send_mult 1025 256

send_mult 2044 256
send_mult 2045 256
send_mult 2046 256
send_mult 2047 256
send_mult 2048 256
send_mult 2049 256

send_mult 4088 256
send_mult 4089 256
send_mult 4090 256
send_mult 4091 256
send_mult 4092 256
send_mult 4093 256
send_mult 4094 256
send_mult 4095 256
send_mult 4096 256
send_mult 4097 256

send_mult 8184 256
send_mult 8185 256
send_mult 8186 256
send_mult 8187 256
send_mult 8188 256
send_mult 8189 256
send_mult 8190 256
send_mult 8191 256
send_mult 8192 256
send_mult 8193 256

# TODO: test multipart messages, i.e., when payload size > 64k-4
