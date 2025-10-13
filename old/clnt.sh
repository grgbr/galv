#!/bin/sh -e

#(while true; do echo "hello"; sleep 1; done) | socat STDIN UNIX:test.sock,socktype=5
# Seqpacket
{ echo "hello0"; sleep 1; echo -n ""; sleep 1; echo "hello1"; }| socat -d -d STDIN UNIX:./sock,socktype=5

# Stream
#echo "hello" | socat -d -d STDIN UNIX:./sock,socktype=1
