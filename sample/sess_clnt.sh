{ echo -e "\x01\x00\x10\x01"; dd if=/dev/zero bs=4097 count=1; } |  nc -U -N ./sock
