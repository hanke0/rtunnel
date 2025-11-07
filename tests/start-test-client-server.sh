#!/bin/bash

set -e

server_pid=
client_pid=
file=$(mktemp)

cleanup() {
	kill $server_pid $client_pid
	rm "${file}"
}

unused_port() {
	for ((port = ${1}; port <= ${2}; port++)); do
		(echo >/dev/tcp/127.0.0.1/$port) >/dev/null && {
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
services = [
    {bind_to = "tcp://127.0.0.1:${client_port}", connect_to = "tcp://127.0.0.1:80"},
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

trap cleanup EXIT

cargo run --bin rtunnel -- -l debug server --config "${file}" &
server_pid=$!
sleep 1
cargo run --bin rtunnel -- -l debug client --config "${file}" &
client_pid=$!
sleep 1

echo "curl http://127.0.0.1:${client_port}"

echo "server pid: $server_pid"
echo "client pid: $client_pid"
while :; do
	sleep 5
	if ! kill -0 $server_pid; then
		echo "server process died"
		break
	fi
	if ! kill -0 $client_pid; then
		echo "client process died"
		break
	fi
done

kill $server_pid $client_pid
wait $server_pid $client_pid
