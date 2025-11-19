#!/bin/bash

usage() {
	echo "Usage: $0 [-t <times=10>] [-c <concurrent=10>] [-b <bytes=1024>] [-l <loop=100>] [--frp] [--direct]"
	exit 1
}

checked_num() {
	if ! [[ "$1" =~ ^[0-9]+$ ]]; then
		usage
	fi
}

times=10
concurrent=10
bytes=1024
loops=100
runmode=rtunnel
echolistento=127.0.0.1:2335
echoconnectto=127.0.0.1:2334
while [ "$#" -gt 0 ]; do
	case "$1" in
	-t | --times)
		checked_num "$2"
		times=$2
		shift 2
		;;
	-c | --concurrent)
		checked_num "$2"
		concurrent=$2
		shift 2
		;;
	-b | --bytes)
		checked_num "$2"
		bytes=$2
		shift 2
		;;
	-l | --loop)
		checked_num "$2"
		loops=$2
		shift 2
		;;
	--frp)
		runmode=frp
		shift
		;;
	--direct)
		runmode=direct
		echoconnectto=127.0.0.1:2335
		shift
		;;
	*)
		usage
		;;
	esac
done

echopid=
server_pid=
client_pid=

severlog=/tmp/bench-server.log
clientlog=/tmp/bench-client.log
echolog=/tmp/echo-bench.log

cleanup() {
	[ -n "$echopid" ] && kill $echopid >/dev/null 2>&1
	[ -n "$server_pid" ] && kill $server_pid >/dev/null 2>&1
	[ -n "$client_pid" ] && kill $client_pid >/dev/null 2>&1
}

trap 'cleanup' EXIT

cargo build --quiet --release --bin echo-bench || exit 1
case "$runmode" in
rtunnel)
	cargo build --quiet --release --bin rtunnel || exit 1
	;;
esac

run_server() {
	case "$runmode" in
	direct)
		return
		;;
	frp)
		tmp/frps --log-level error -c tmp/frps.toml >"${severlog}" 2>&1 &
		;;
	*)
		target/release/rtunnel -l error server >"${severlog}" 2>&1 &
		;;
	esac
	server_pid=$!
}

run_client() {
	case "$runmode" in
	direct)
		return
		;;
	frp)
		tmp/frpc -c tmp/frpc.toml >${clientlog} 2>&1 &
		;;
	*)
		target/release/rtunnel -l error client >${clientlog} 2>&1 &
		;;
	esac
	client_pid=$!
}

get_version() {
	case "$runmode" in
	direct)
		return
		;;
	frp)
		echo "frp" "$(tmp/frpc --version)"
		;;
	*)
		target/release/rtunnel --version
		;;
	esac
}

run_echo_bench() {
	target/release/echo-bench $echoconnectto $echolistento "$concurrent" "$times" "$bytes" "$loops" 2>${echolog} &
	echopid=$!
}

is_alive() {
	[ -z "$1" ] && return
	kill -0 $1 >/dev/null 2>&1
}

get_cpu() {
	[ -z "$1" ] && return
	local utime1 stime1
	read -r _ _ _ _ _ _ _ _ _ _ _ _ _ utime1 stime1 _ <"/proc/$1/stat"
	echo $((utime1 + stime1))
}

get_uptime() {
	local updateime
	read -r updateime _ <"/proc/uptime"
	echo $updateime
}

echo "tunnel: $runmode"
run_server
sleep 10
run_client
sleep 10
client_cpu=$(get_cpu $client_pid)
server_cpu=$(get_cpu $server_pid)
uptime=$(get_uptime)
run_echo_bench
sleep 10

echo >&2 "server pid: $server_pid"
echo >&2 "client pid: $client_pid"
echo >&2 "echo-bench pid: $echopid"
echo >&2 "version: $(get_version)"
echo >&2 "server-log: $severlog"
echo >&2 "client-log: $clientlog"
echo >&2 "echo-bench-log: $echolog"

while :; do
	sleep 5
	if ! is_alive $server_pid; then
		echo >&2 "server process died"
		break
	fi
	if ! is_alive $client_pid; then
		echo >&2 "client process died"
		break
	fi
	if ! is_alive $echopid; then
		echo >&2 "echo-bench process died"
		break
	fi
done

server_cpu1=$(get_cpu $server_pid)
client_cpu1=$(get_cpu $client_pid)
updateime1=$(get_uptime)
clock_tick=$(getconf CLK_TCK)
echo "server-cpu: $(echo "c=($server_cpu1 - $server_cpu)/$clock_tick/($updateime1 - $uptime)*100; scale=2; c" | bc -l)%"
echo "client-cpu: $(echo "c=($client_cpu1 - $client_cpu)/$clock_tick/($updateime1 - $uptime)*100; scale=2; c" | bc -l)%"
echo

cleanup
wait $server_pid $client_pid $echopid
