#!/bin/bash

usage() {
	echo "Usage: $0 [-t <times=10>] [-c <concurrent=10>] [-b <bytes=1024>] [-l <loop=100>] [--http]"
	echo "          [--direct] [--rtunnel-tcp] [--rtunnel-tls] [--rtunnel-quic]"
	echo "          [--frp-tcp] [--frp-tls]"
	echo "          [--rathole-tcp] [--rathole-tls]"
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
runmode=rtunnel-tls
config=tmp/rtunnel/rtunnel-tls.toml
frpsconfig=tmp/frp/frps-tcp.toml
frpcconfig=tmp/frp/frpc-tcp.toml
ratholeconfig=tmp/rathole/rathole-tls.toml
http_rps=false
extra_options=()

benchlistento=127.0.0.1:2335
benchconnectto=127.0.0.1:2334
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
	--rtunnel-tcp)
		runmode=rtunnel-tcp
		config=tmp/rtunnel/rtunnel-tcp.toml
		shift
		;;
	--rtunnel-tls)
		runmode=rtunnel-tls
		config=tmp/rtunnel/rtunnel-tcp.toml
		shift
		;;
	--rtunnel-quic)
		runmode=rtunnel-quic
		config=tmp/rtunnel/rtunnel-quic.toml
		shift
		;;
	--frp-tcp)
		runmode=frp-tcp
		frpsconfig=tmp/frp/frps-tcp.toml
		frpcconfig=tmp/frp/frpc-tcp.toml
		shift
		;;
	--frp-tls)
		runmode=frp-tls
		frpsconfig=tmp/frp/frps-tls.toml
		frpcconfig=tmp/frp/frpc-tls.toml
		shift
		;;
	--rathole-tcp)
		ratholeconfig=tmp/rathole/rathole-tcp.toml
		runmode=rathole-tcp
		shift
		;;
	--rathole-tls)
		ratholeconfig=tmp/rathole/rathole-tls.toml
		runmode=rathole-tls
		shift
		;;
	--direct)
		runmode=direct
		benchconnectto=127.0.0.1:2335
		shift
		;;
	--http)
		http_rps=true
		shift
		;;
	*)
		usage
		;;
	esac
done

benchpid=
serverpid=
clientpid=

serverlog=tmp/bench-server.log
clientlog=tmp/bench-client.log
benchlog=tmp/bench.log

cleanup() {
	[ -n "$benchpid" ] && kill $benchpid >/dev/null 2>&1
	[ -n "$serverpid" ] && kill $serverpid >/dev/null 2>&1
	[ -n "$clientpid" ] && kill $clientpid >/dev/null 2>&1
}

trap 'cleanup' EXIT
mkdir -p tmp
cargo build --quiet --release --bin echo-bench || exit 1
case "$runmode" in
rtunnel*)
	cargo build "${extra_options[@]}" --quiet --release --bin rtunnel || exit 1
	;;
esac

export RUST_LOG=warn

run_server() {
	case "$runmode" in
	direct)
		return
		;;
	frp*)
		echo >&2 "frps config: ${frpsconfig}"
		tmp/frp/frps -c "${frpsconfig}" >"${serverlog}" 2>&1 &
		;;
	rathole*)
		echo >&2 "rathole config: ${ratholeconfig}"
		tmp/rathole/rathole -s "${ratholeconfig}" >"${serverlog}" 2>&1 &
		;;
	*)
		echo >&2 "rtunnel config: ${config}"
		target/release/rtunnel -l warn server -c "$config" >"${serverlog}" 2>&1 &
		;;
	esac
	serverpid=$!
}

run_client() {
	case "$runmode" in
	direct)
		return
		;;
	frp*)
		echo >&2 "frpc config: ${frpcconfig}"
		tmp/frp/frpc -c "${frpcconfig}" >${clientlog} 2>&1 &
		;;
	rathole*)
		echo >&2 "rathole config: ${ratholeconfig}"
		tmp/rathole/rathole -c "${ratholeconfig}" >${clientlog} 2>&1 &
		;;
	*)
		echo >&2 "rtunnel config: ${config}"
		target/release/rtunnel -l warn client -c "${config}" >${clientlog} 2>&1 &
		;;
	esac
	clientpid=$!
}

grep_version() {
	"$@" 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z\.-]+)?(\+[0-9A-Za-z\.-]+)?'
}

get_version() {
	case "$runmode" in
	direct)
		echo "direct"
		return
		;;
	frp*)
		echo "frp" "$(grep_version tmp/frpc --version)"
		;;
	rathole*)
		echo "rathole" "$(grep_version tmp/rathole --version)"
		;;
	*)
		echo rtunnel "$(grep_version target/release/rtunnel --version)"
		;;
	esac
}

run_bench() {
	case "$http_rps" in
	true)
		printf '%s' '

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

' >tmp/nginx.conf
		nginx -g "daemon off;" -p tmp -c nginx.conf >${benchlog} 2>&1 &
		benchpid=$!
		n="$((times * concurrent * loops))"
		echo >&2 "running ab -n $n -c $concurrent -k -r http://127.0.0.1:2334/"
		ab -n "$n" -c "$concurrent" -k -r http://${benchconnectto}/ 2>"${benchlog}" | tee -a "${benchlog}" | awk -F: '
		/Failed requests/ { print "failed: ", $2 }
		/Requests per second/ { print "rps: ", $2 }
		/Transfer rate/ { print "throughput: ", $2 }
		'
		kill $benchpid
		;;
	*)
		target/release/echo-bench $benchconnectto $benchlistento "$concurrent" "$times" "$bytes" "$loops" 2>${benchlog} &
		benchpid=$!
		;;
	esac
}

is_alive() {
	[ -z "$1" ] && return
	kill -0 "$1" >/dev/null 2>&1
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
sleep 3
run_client
sleep 3
client_cpu=$(get_cpu $clientpid)
server_cpu=$(get_cpu $serverpid)
uptime=$(get_uptime)
run_bench
sleep 3

echo >&2 "server pid: $serverpid"
echo >&2 "client pid: $clientpid"
echo >&2 "bench pid: $benchpid"
echo >&2 "version: $(get_version)"
echo >&2 "server-log: $serverlog"
echo >&2 "client-log: $clientlog"
echo >&2 "bench-log: $benchlog"

while :; do
	sleep 5
	if ! is_alive $serverpid; then
		echo >&2 "server process died"
		break
	fi
	if ! is_alive $clientpid; then
		echo >&2 "client process died"
		break
	fi
	if ! is_alive $benchpid; then
		echo >&2 "bench process died"
		break
	fi
done

server_cpu1=$(get_cpu $serverpid)
client_cpu1=$(get_cpu $clientpid)
uptime1=$(get_uptime)

cpu1="($server_cpu1 - $server_cpu)/($uptime1 - $uptime)*100"
cpu2="($client_cpu1 - $client_cpu)/($uptime1 - $uptime)*100"
echo >&2 "server-cpu: $cpu1"
echo >&2 "client-cpu: $cpu2"

echo "server-cpu: $(echo "scale=3; $cpu1" | bc -l 2>/dev/null)%"
echo "client-cpu: $(echo "scale=3; $cpu2" | bc -l 2>/dev/null)%"
echo

cleanup
wait $serverpid $clientpid $benchpid
