#!/bin/bash

usage() {
	echo "Usage: $0 [-t <times=10>] [-c <concurrent=10>] [-b <bytes=1024>] [-l <loop=100>] [--frp] [--direct] [--tcp] [--frp-tls] [--http-rps]"
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
config=tmp/rtunnel.toml
frpsconfig=tmp/frps.toml
frpcconfig=tmp/frpc.toml
http_rps=false
extra_options=()


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
	--frp-tls)
		runmode=frp-tls
		frpsconfig=tmp/frps-tls.toml
		frpcconfig=tmp/frpc-tls.toml
		shift
		;;
	--direct)
		runmode=direct
		echoconnectto=127.0.0.1:2335
		shift
		;;
	--tcp)
		runmode=rtunnel-tcp
		config=tmp/rtunnel-tcp.toml
		shift
		;;
	--http-rps)
		http_rps=true
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
rtunnel|rtunnel-tcp)
	cargo build "${extra_options[@]}" --quiet --release --bin rtunnel || exit 1
	cargo run -- example-config example.com >tmp/rtunnel.toml || exit 1
	cargo run -- example-config --kind tcp example.com >tmp/rtunnel-tcp.toml || exit 1
	chmod 600 tmp/rtunnel.toml tmp/rtunnel-tcp.toml
	;;
esac

run_server() {
	case "$runmode" in
	direct)
		return
		;;
	frp|frp-tls)
		echo >&2 "frps config: ${frpsconfig}"
		tmp/frps -c "${frpsconfig}" >"${severlog}" 2>&1 &
		;;
	*)
		echo >&2 "rtunnel config: ${config}"
		target/release/rtunnel -l error server -c "$config" >"${severlog}" 2>&1 &
		;;
	esac
	server_pid=$!
}

run_client() {
	case "$runmode" in
	direct)
		return
		;;
	frp|frp-tls)
		echo >&2 "frpc config: ${frpcconfig}"
		tmp/frpc -c "${frpcconfig}" >${clientlog} 2>&1 &
		;;
	*)
		echo >&2 "rtunnel config: ${config}"
		target/release/rtunnel -l error client -c "${config}" >${clientlog} 2>&1 &
		;;
	esac
	client_pid=$!
}

get_version() {
	case "$runmode" in
	direct)
		return
		;;
	frp|frp-tls)
		echo "frp" "$(tmp/frpc --version)"
		;;
	*)
		target/release/rtunnel --version
		;;
	esac
}

run_bench() {
	case "$http_rps" in
	true)
		echo '

worker_processes 1;
error_log /dev/stderr info;
pid nginx.pid;

events {
    worker_connections   2000;
}

http {
    server {
        listen 2335;
		access_log off;

        location / {
				return 200 "Hello, World!\n";
        }
    }
}	

' > tmp/nginx.conf
		nginx -g "daemon off;" -c tmp/nginx.conf >${severlog} 2>&1 &
		echopid=$!
		ab -n 1000 -c 1 -k -r http://127.0.0.1:2334/
		kill $echopid
		;;
	*)
		target/release/echo-bench $echoconnectto $echolistento "$concurrent" "$times" "$bytes" "$loops" 2>${echolog} &
		echopid=$!
		;;
	esac
}

is_alive() {
	[ -z "$1" ] && return
	kill -0 $1 >/dev/null 2>&1
}

get_cpu() {
	local utime stime clk_tck
	[ -z "$1" ] && return
	if [ -f "/proc/$1/stat" ]; then
		read -r _ _ _ _ _ _ _ _ _ _ _ _ _ utime stime _ <"/proc/$1/stat"
		clk_tck=$(getconf CLK_TCK)
		echo $(((utime + stime) * 1000 / clk_tck))
	else
		ps -p $1 -o time= | awk -F: '{ total=0; m=1; } { for (i=0; i < NF; i++) {total += $(NF-i)*m; m *= i >= 2 ? 24 : 60 }} {print total*1000}'
	fi
}

get_uptime() {
	date +%s%N | cut -b1-13
}

echo "tunnel: $runmode"
run_server
sleep 10
run_client
sleep 10
client_cpu=$(get_cpu $client_pid)
server_cpu=$(get_cpu $server_pid)
uptime=$(get_uptime)
run_bench
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
uptime1=$(get_uptime)

cpu1="($server_cpu1 - $server_cpu)/($uptime1 - $uptime)*100"
cpu2="($client_cpu1 - $client_cpu)/($uptime1 - $uptime)*100"
echo >&2 "server-cpu: $cpu1"
echo >&2 "client-cpu: $cpu2"

echo "server-cpu: $(echo "scale=3; $cpu1" | bc -l 2>/dev/null)%"
echo "client-cpu: $(echo "scale=3; $cpu2" | bc -l 2>/dev/null)%"
echo

cleanup
wait $server_pid $client_pid $echopid
