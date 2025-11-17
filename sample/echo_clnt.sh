#!/bin/sh -e

ECHO_SRV="$HOME/devel/test/out/root/bin/galv-smpl-echo-srv"
BLOCKSIZES=(512 768 999 1024 1025 1460 1500 2047 2048 2049 4095 4096 4097)

workdir="$TMPDIR/galv-smpl-echo-clnt"
inpath="/dev/urandom"
insize=$((256*1024*1024))
refpath="$workdir/ref.dat"
outpath="$workdir/out.dat"

cleanup()
{
	trap - EXIT

	if [ "$stat" -ne "0" ]; then
		printf "\nThere has been some FAILURES.\n" >&2
	else
		printf "\nAll tests PASSED.\n" >&2
	fi

	rm -rf $workdir

	exit $stat
}

wait_pid()
{
	local sec=5

	while [ $sec -gt 0 ]; do
		if [ ! -d /proc/$pid ]; then
			break
		fi
		sleep 1
		sec=$((sec - 1))
	done

	if [ $sec -le 0 ]; then
		kill -KILL $pid || true
		return 1
	fi

	return 0
}

show()
{
	local size="$1"
	local stat="$2"

	printf "%10u ... %s\n" "$size" "$stat" >&2
}

run()
{
	local blksize=$1
	local pid

	$ECHO_SRV >/dev/null 2>&1 &
	pid=$!

	rm -f "$outpath"
	dd if="$refpath" bs=$blksize status=none | nc -N -U ./sock > "$outpath"

	kill -TERM $pid
	if ! wait_pid "$pid"; then
		show "$blksize" "fail"
		return 1
	fi

	if ! cmp "$refpath" "$outpath"; then
		show "$blksize" "FAILURE"
		return 1
	fi

	show "$blksize" "pass"
	return 0
}

mkdir -p "$workdir"
cd "$workdir"
if [ ! -f "$refpath" ]; then
	dd if="$inpath" bs=4096 count=$((insize / 4096)) status=none | \
		base64 --wrap=50 > "$refpath"
fi

printf "Testing %u bytes long 'echo' client / server transfers...\n\n" \
       "$(stat --printf="%s" $refpath)"
printf "%10.10s ... %s\n" "BLOCK SIZE" "RESULT" >&2

stat=0
trap 'cleanup' EXIT
for bs in ${BLOCKSIZES[@]}; do
	if ! run "$bs" ; then
		stat=1
	fi
done
