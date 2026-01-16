#!/bin/sh -e

# Test some invalib message combinations...

send()
{
	local msg="$1"

	/bin/echo -en "$msg" | nc -U -N ./sock | hexdump -C
	sync
}

send "\x01\x00\x02\x00\x01\x00\x03\x00\x00\x92\x01\x02"
send "\x01\x80\x00\x00\x00\x92\x01\x02"
send "\x03\x00\x03\x00\x00\x92\x01\x02"
