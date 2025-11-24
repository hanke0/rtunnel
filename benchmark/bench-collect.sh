#!/bin/bash

awk -F': ' '
BEGIN {
    direct_data[0] = "direct"
    rtunnel_data[0] = "rtunnel"
    rtunnel_tcp_data[0] = "rtunnel-tcp"
    frp_data[0] = "frp"
    frp_tls_data[0] = "frp-tls"
    name=""
    tunnel_count = 0
}
{
    if ($1 == "tunnel") {
        name = $2
        data[name, "tunnel"] = $2
        tunnels[++tunnel_count] = name
    }
    if ($1 == "failed") {
        data[name, "failed"] = $2
    }
    if ($1 == "throughput") {
        data[name, "throughput"] = $2
    }
    if ($1 == "server-cpu") {
        data[name, "server-cpu"] = $2
    }
    if ($1 == "client-cpu") {
        data[name, "client-cpu"] = $2
    }
}
END {
    print "| tunnel | failed | throughput | server-cpu |client-cpu |"
    print "| --- | --- | --- | --- | --- |"
    for (i = 1; i <= tunnel_count; i++) {
        tunnel_name = tunnels[i]
        print "| " tunnel_name " | " data[tunnel_name, "failed"] " | " data[tunnel_name, "throughput"] " | " data[tunnel_name, "server-cpu"] " | " data[tunnel_name, "client-cpu"] " |"
    }
}
' "${1:-tmp/benchmark.txt}"