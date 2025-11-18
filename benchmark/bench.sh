#!/bin/bash

echopid=
server_pid=
client_pid=

cleanup() {
	kill $server_pid $client_pid $echopid
}

trap 'cleanup' EXIT

cargo build --release --bin echo-bench || exit 1
cargo build --release --bin rtunnel || exit 1

run_server() {
	cargo run --bin rtunnel -- -l error server >/dev/null 2>&1 &
	server_pid=$!
}

run_client() {
	cargo run --bin rtunnel -- -l error client >/dev/null 2>&1 &
	client_pid=$!
}

run_echo_bench() {
	target/release/echo-bench 127.0.0.1:2334 127.0.0.1:2335 1000 1024 2>&1 &
	echopid=$!
}

is_alive() {
	kill -0 $1
}

run_server
sleep 3
run_client
sleep 3
run_echo_bench
sleep 3

echo "server pid: $server_pid"
echo "client pid: $client_pid"
echo "echo-bench pid: $echopid"

while :; do
	sleep 5
	if ! is_alive $server_pid; then
		echo "server process died"
		break
	fi
	if ! is_alive $client_pid; then
		echo "client process died"
		break
	fi
	if ! is_alive $echopid; then
		echo "echo-bench process died"
		break
	fi
done

cleanup
wait $server_pid $client_pid $echopid
