#!/bin/bash

download_tar() {
    echo "Downloading $2"
    wget -q -O /tmp/a.tar.gz "$2"
    rm -rf /tmp/tarball
    mkdir /tmp/tarball
    tar -xf /tmp/a.tar.gz -C /tmp/tarball
    rm -rf /tmp/a.tar.gz
    find /tmp/tarball -name "$1" -exec echo cp -f {} tmp/ \; -exec cp -f {} tmp/ \;
    rm -rf /tmp/tarball
}

download_tar "frp[cs]" \
    "https://github.com/fatedier/frp/releases/download/v0.65.0/frp_0.65.0_linux_amd64.tar.gz"

write_tmp_config() {
    if [ ! -d tmp ]; then
        mkdir tmp
    fi
    echo "write content to file: $1"
    cat - >tmp/"$1"
}

write_tmp_config frpc.toml <<__EOF__
serverAddr = "127.0.0.1"
serverPort = 2333

[[proxies]]
name = "test-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2335
remotePort = 2334
__EOF__

write_tmp_config frps.toml <<__EOF__
bindPort = 2333
__EOF__
