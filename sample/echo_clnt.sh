#!/bin/sh -e

ECHO_SRV="@@BINDIR@@/galv-smpl-echo-srv"
BLOCKSIZES="512 768 999 1024 1025 1460 1500 2047 2048 2049 4095 4096 4097"

inpath="/dev/urandom"
insize=$((256*1024*1024))
tmpdir=${TMPDIR:-/tmp}
workdir="$tmpdir/galv-smpl-echo-clnt.$$"
refpath="$workdir/ref.dat"
sockpath="./sock"

cleanup()
{
	trap - EXIT INT QUIT TERM HUP

	if [ $stat -ne 0 ] || [ $fail -ne 0 ]; then
		printf "\nThere has been some FAILURES.\n" >&2
		stat=1
	else
		printf "\nAll tests PASSED.\n" >&2
	fi

	pkill --parent $$ --signal KILL || true
	rm -rf $workdir

	exit $stat
}

wait_pid()
{
	local pid=$1
	local sec=10

	while [ $sec -gt 0 ]; do
		if [ ! -d /proc/$pid ]; then
			break
		fi
		sleep 1
		sec=$((sec - 1))
	done

	if [ $sec -le 0 ]; then
		kill -KILL $pid >/dev/null 2>&1 || true
		return 1
	fi

	return 0
}

wait_pids()
{
	local pids="$@"
	local ret=0

	for p in $pids; do
		if ! wait_pid "$p"; then
			ret=1
		fi
	done

	return $ret
}

show()
{
	local size="$1"
	local res="$2"

	printf "%10u ... %s\n" "$size" "$res" >&2
}

spawn_srv()
{
	local cnt=3
	local pid

	$ECHO_SRV >/dev/null 2>&1 &
	pid=$!

	while [ $cnt -gt 0 ]; do
		sync
		if [ -S "$sockpath" ]; then
			break;
		fi

		sleep 1

		cnt=$((cnt - 1))
	done
	
	if [ ! -d "/proc/$pid" ]; then
		printf "Failed to spawn service\n" >&2
		return 1
	fi

	echo "$pid"

	return 0
}

do_xfer()
{
	local out="$1"
	local blksz=$2

	rm -f "$out"

	dd if="$refpath" bs=$blksz status=none | nc -N -U "$sockpath" > "$out"
	sync
}

check_xfer()
{
	local out="$1"
	local blksz=$2

	do_xfer "$out" "$blksz"
	if ! cmp "$refpath" "$out" 2>/dev/null; then
		return 1
	fi

	return 0
}

test_single_conn_xfer()
{
	local out="$1"
	local blksz=$2
	local pid
	local ret=0

	if ! pid=$(spawn_srv); then
		return 1
	fi

	if ! check_xfer "$out" "$blksz"; then
		ret=1
	fi

	kill -TERM $pid >/dev/null 2>&1
	if ! wait_pid "$pid"; then
		ret=1
	fi

	if [ $ret -ne 0 ]; then
		show "$blksz" "fail"
	else
		show "$blksz" "pass"
	fi

	return $ret
}

test_multi_conn_xfer()
{
	local out="$1"
	local pid
	local blksz
	local ret=0

	if ! pid=$(spawn_srv); then
		return 1
	fi

	for blksz in $BLOCKSIZES; do
		if ! check_xfer "$out" "$blksz"; then
			show "$blksz" "fail"
			ret=1
		else
			show "$blksz" "pass"
		fi
	done

	kill -TERM $pid >/dev/null 2>&1
	if ! wait_pid "$pid"; then
		ret=1
	fi

	return $ret
}

test_simult_conn_xfer()
{
	local  out="$1"
	local  blksz=$2
	local  srv_pid
	local  job
	local  clnt_pids=""
	local  ret=0

	if ! srv_pid=$(spawn_srv); then
		return 1
	fi

	job=0
	while [ $job -lt $jobnr ]; do
		do_xfer "$out.$job" "$blksz" &
		clnt_pids="$clnt_pids $!"
		job=$((job + 1))
	done

	if ! wait_pids "$clnt_pids"; then
		ret=1
	fi

	kill -TERM $srv_pid >/dev/null 2>&1
	if ! wait_pid "$srv_pid"; then
		ret=1
	fi

	if [ $ret -eq 0 ]; then
		job=0
		while [ $job -lt $jobnr ]; do
			if ! cmp "$refpath" "$out.$job" 2>/dev/null; then
				ret=1
				break
			fi
			job=$((job + 1))
		done
	fi

	if [ $ret -ne 0 ]; then
		show "$blksz" "fail"
		return 1
	else
		show "$blksz" "pass"
		return 0
	fi
}

test_single_conn_term()
{
	local out="$1"
	local blksz=$2
	local srv_pid
	local clnt_pid

	if ! srv_pid=$(spawn_srv); then
		return 1
	fi

	rm -f "$out"
	dd if="$refpath" bs=$blksz status=none | \
		nc -U "$sockpath" > "$out" &
	clnt_pid=$!
	sync

	kill -TERM $srv_pid >/dev/null 2>&1
	if ! wait_pid "$srv_pid"; then
		show "$blksz" "fail"
		return 1
	fi
	if ! wait_pid "$clnt_pid"; then
		show "$blksz" "fail"
		return 1
	fi

	show "$blksz" "pass"
	return 0
}

do_endless_xfer()
{
	local out="$1"
	local blksz=$2

	rm -f "$out"

	dd if="$refpath" bs=$blksz status=none | nc -U "$sockpath" > "$out"
	sync
}

test_simult_conn_term()
{
	local out="$1"
	local srv_pid
	local job
	local blksz
	local clnt_pids=""
	local pid
	local ret=0

	if ! srv_pid=$(spawn_srv); then
		return 1
	fi
	
	job=0
	for blksz in $BLOCKSIZES; do
		do_endless_xfer "$out.$job" "$blksz" &
		clnt_pids="$clnt_pids $!"
		job=$((job + 1))
	done

	# Give clients enought time to start.
	sleep 2
	
	kill -TERM $srv_pid >/dev/null 2>&1
	if ! wait_pid "$srv_pid"; then
		ret=1
	fi

	if ! wait_pids "$clnt_pids"; then
		ret=1
	fi

	if [ $ret -ne 0 ]; then
		echo "fail" >&2
		return 1
	else
		echo "pass" >&2
		return 0
	fi
}

if ! jobnr=$(lscpu --online --parse=CPU | grep -v '^#' | wc -l); then
	echo "failed to probe for available CPUs" >&2
fi

mkdir -p "$workdir"
cd "$workdir"
if [ ! -f "$refpath" ]; then
	dd if="$inpath" bs=4096 count=$((insize / 4096)) status=none | \
		base64 --wrap=50 > "$refpath"
fi

fail=0
stat=1
trap 'cleanup' EXIT INT QUIT TERM HUP

title=$(printf "Running 'echo' client / server with %u bytes long payload" \
	"$(stat --printf="%s" $refpath)")
printf "### %*.*s ###\n" "${#title}" "${#title}" "" >&2
printf "### %*.*s ###\n" "${#title}" "${#title}" "$title" >&2
printf "### %*.*s ###\n" "${#title}" "${#title}" "" >&2

printf "\nSingle connection transfers\n" >&2
printf "===========================\n\n" >&2
printf "%10.10s ... %s\n" "Block size" "Result" >&2
for bs in $BLOCKSIZES; do
	if ! test_single_conn_xfer "$workdir/out.dat" "$bs" ; then
		fail=$((fail + 1))
	fi
done

printf "\nMultiple connection transfers\n" >&2
printf "=============================\n\n" >&2
printf "%10.10s ... %s\n" "Block size" "Result" >&2
if ! test_multi_conn_xfer "$workdir/out.dat" ; then
	fail=$((fail + 1))
fi

printf "\nConcurrent connection transfers\n" >&2
printf "===============================\n\n" >&2
printf "%10.10s ... %s\n" "Block size" "Result" >&2
for bs in $BLOCKSIZES; do
	if ! test_simult_conn_xfer "$workdir/out.dat" "$bs" ; then
		fail=$((fail + 1))
	fi
done

printf "\nSingle connection termination\n" >&2
printf "=============================\n\n" >&2
printf "%10.10s ... %s\n" "Block size" "Result" >&2
for bs in $BLOCKSIZES; do
	if ! test_single_conn_term "$workdir/out.dat" "$bs" ; then
		fail=$((fail + 1))
	fi
done

printf "\nConcurrent connection termination\n" >&2
printf "=================================\n\n" >&2
if ! test_simult_conn_term "$workdir/out.dat" ; then
	fail=$((fail + 1))
fi

stat=0
