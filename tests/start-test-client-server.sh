#!/bin/bash

set -e

runmode="$1"

server_pid=
client_pid=
file=$(mktemp)

cleanup() {
	kill $server_pid $client_pid
	rm -f "${file}"
}

unused_port() {
	for ((port = ${1}; port <= ${2}; port++)); do
		(echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1 && {
			continue
		} || {
			echo $port
			return
		}
	done
	echo >&2 "no unused port found"
	exit 1
}

server_port=$(unused_port 2000 5000)
client_port=$(unused_port 6000 8000)

echo "server port: ${server_port}"
echo "client port: ${client_port}"

cat >"${file}" <<EOF
[[clients]]
private_key = "qQUDm6dbFya0x5/1p5sibl+sW0MioHi2ydqxvhnatpY="
public_key = "8e5CzqP3Z2SCGpxZyT5NEiJQWbAnrS6s77SC+ZFIbhA="

server_public_key = "t52DtA5i4SJWQYXtrOrM4GikogBe7KcQ5CwwGtS8sf4="
server_address = "tcp://127.0.0.1:${server_port}"
allowed_addresses = [
    "tcp://127.0.0.1:${client_port}",
]
# max_connections = 1024
# idle_connections = 10

[[servers]]
private_key = "I7KWrWOdkVAgTCwd1eR18RDXEnGqDPxGaOP/K+vzHrs="
public_key = "t52DtA5i4SJWQYXtrOrM4GikogBe7KcQ5CwwGtS8sf4="
client_public_key = "8e5CzqP3Z2SCGpxZyT5NEiJQWbAnrS6s77SC+ZFIbhA="

listen = "tcp://127.0.0.1:${server_port}"
services = [
    {bind_to = "tcp://127.0.0.1:${client_port}", connect_to = "tcp://127.0.0.1:80"},
]
EOF

chmod 400 "${file}"

trap cleanup EXIT

run_server() {
	cargo run --bin rtunnel -- -l debug server --config "${file}" &
	server_pid=$!
}

run_client() {
	cargo run --bin rtunnel -- -l debug client --config "${file}" &
	client_pid=$!
}

case "$runmode" in
s|server|serve)
	run_server
	;;
c|client)
	run_client
	;;
*)
	run_server
	sleep 1
	run_client
	sleep 1
	;;
esac

sleep 1
echo "curl http://127.0.0.1:${client_port}"

echo "server pid: $server_pid"
echo "client pid: $client_pid"

server_alive() {
	if [ -z "$server_pid" ]; then
		return 0
	fi
	if ! kill -0 $server_pid; then
		return 1
	fi
	return 0
}

client_alive() {
	if [ -z "$client_pid" ]; then
		return 0
	fi
	if ! kill -0 $client_pid; then
		return 1
	fi
	return 0
}

while :; do
	sleep 5
	if ! server_alive; then
		echo "server process died"
		break
	fi
	if ! client_alive; then
		echo "client process died"
		break
	fi
done

kill $server_pid $client_pid
wait $server_pid $client_pid
