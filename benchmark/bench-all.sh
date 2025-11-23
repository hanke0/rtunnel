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

awk -F': ' '
BEGIN {
    direct_data[0] = "direct"
    rtunnel_data[0] = "rtunnel"
    rtunnel_tcp_data[0] = "rtunnel-tcp"
    frp_data[0] = "frp"
    frp_tls_data[0] = "frp-tls"
    name=""
}
{
    ($1 == "tunnel") {
        name = $2
        data[$name]["tunnel"] = $2
    }
    ($1 == "connect_spend_ns") {
        data[name]["connect_spend_ns"] = $2
    }
    ($1 == "Throughput") {
        data[name]["Throughput"] = $2
    }
    ($1 == "server-cpu") {
        data[name]["server-cpu"] = $2
    }
    ($1 == "client-cpu") {
        data[name]["client-cpu"] = $2
    }
}
END {
    print "| tunnel | connect_spend_ns | Throughput | server-cpu |client-cpu |"
    print "| --- | --- | --- | --- | --- |"
    for (name in data) {
        print "| " name " | " data[name]["connect_spend_ns"] " | " data[name]["Throughput"] " | " data[name]["server-cpu"] " | " data[name]["client-cpu"] " |"
    }
}
' tmp/benchmark.txt
