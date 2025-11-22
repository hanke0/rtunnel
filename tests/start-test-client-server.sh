#!/bin/bash

set -e

runmode="$1"

server_pid=
client_pid=
echopid=
serverlog=/tmp/server.log
clientlog=/tmp/client.log
echolog=/tmp/echo.log

cleanup() {
	kill $server_pid $client_pid $echopid
}

trap cleanup EXIT

run_server() {
	cargo run --bin rtunnel -- -l debug server >"${serverlog}" 2>&1 &
	server_pid=$!
	echo "server log: ${serverlog}"
}

run_client() {
	cargo run --bin rtunnel -- -l debug client >"${clientlog}" 2>&1 &
	client_pid=$!
	echo "client log: ${clientlog}"
}

run_echo() {
	cargo run --bin echo-server -- 127.0.0.1:2335 >"${echolog}" 2>&1 &
	echopid=$!
	echo "echo log: ${echolog}"
}

case "$runmode" in
s | server | serve)
	run_server
	;;
c | client)
	run_client
	;;
*)
	run_server
	sleep 1
	run_client
	sleep 1
	run_echo
	sleep 1
	;;
esac

sleep 1
echo "curl http://127.0.0.1:2334"

echo "server pid: $server_pid"
echo "client pid: $client_pid"
echo "echo pid: $echopid"

is_alive() {
	[ -z "$1" ] && return
	kill -0 $1 >/dev/null 2>&1
}

test_port() {
	local port=$1
	data=$(echo "hello" | cargo run --bin echo-client -- 127.0.0.1:$port)
	echo >&2 "recv data: $data"

	[ "$data" != "hello" ] && echo "recv data is not hello for port: $port" && exit 1
	echo >&2 "recv data is hello for port: $port"
}

test_port 2335
test_port 2334
