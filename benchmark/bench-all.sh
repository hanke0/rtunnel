#!/bin/bash

usage() {
	echo "Usage: $0 [-t <times=10>] [-c <concurrent=10>] [-b <bytes=1024>] [-l <loop=100>] [--http]"
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
extra_args=()

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
	--http)
		extra_args+=("--http")
		shift
		;;
	*)
		usage
		;;
	esac
done

echo >tmp/benchmark.txt
mkdir -p tmp

run_bench() {
	echo "run $1"
	./benchmark/bench.sh "$1" --times $times --concurrent $concurrent -b $bytes -l $loops "${extra_args[@]}" | tee -a tmp/benchmark.txt
}

run_bench --direct
run_bench --rtunnel-tcp
run_bench --frp-tcp
run_bench --rathole-tcp
run_bench --rtunnel-tls
run_bench --frp-tls
run_bench --rathole-tls

./benchmark/bench-collect.sh tmp/benchmark.txt
