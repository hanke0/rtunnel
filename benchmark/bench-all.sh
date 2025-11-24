#!/bin/bash

usage() {
	echo "Usage: $0 [-t <times=10>] [-c <concurrent=10>] [-b <bytes=1024>] [-l <loop=100>]"
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
	*)
		usage
		;;
	esac
done

echo >tmp/benchmark.txt
mkdir -p tmp
echo "run direct"
./benchmark/bench.sh --direct --times $times --concurrent $concurrent -b $bytes -l $loops | tee -a tmp/benchmark.txt
echo "run rtunnel"
./benchmark/bench.sh --times $times --concurrent $concurrent -b $bytes -l $loops | tee -a tmp/benchmark.txt
echo "run rtunnel-tcp"
./benchmark/bench.sh --tcp --times $times --concurrent $concurrent -b $bytes -l $loops | tee -a tmp/benchmark.txt
echo "run frp"
./benchmark/bench.sh --frp --times $times --concurrent $concurrent -b $bytes -l $loops | tee -a tmp/benchmark.txt
echo "run frp-tls"
./benchmark/bench.sh --frp-tls --times $times --concurrent $concurrent -b $bytes -l $loops | tee -a tmp/benchmark.txt

columns=(
	connect_spend_ns
	Throughput
	server-cpu
	client-cpu
)
direct_data=()
rtunnel_data=()
rtunnel_tcp_data=()
frp_data=()
frp_tls_data=()

./benchmark/bench-collect.sh tmp/benchmark.txt
