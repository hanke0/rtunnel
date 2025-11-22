#!/bin/bash

download_tar() {
    echo "Downloading $2"
    wget -q -O /tmp/a.tar.gz "$2"
    rm -rf /tmp/tarball
    mkdir /tmp/tarball
    tar -xf /tmp/a.tar.gz -C /tmp/tarball
    rm -rf /tmp/a.tar.gz
    mkdir -p tmp
    find /tmp/tarball -name "$1" -exec echo cp -f {} tmp/ \; -exec cp -f {} tmp/ \;
    rm -rf /tmp/tarball
}

case $(uname -o)_$(uname -m) in
    *Linux_x86_64)
        URL="https://github.com/fatedier/frp/releases/download/v0.65.0/frp_0.65.0_linux_amd64.tar.gz"
        ;;
    Darwin_arm64)
        URL="https://github.com/fatedier/frp/releases/download/v0.65.0/frp_0.65.0_darwin_arm64.tar.gz"
        ;;
    *)
        echo "unsupported architecture"
        exit 1
        ;;
esac

[ "$1" = "cfg" ] || download_tar "frp[cs]" "$URL"

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
log.level = "error"

[[proxies]]
name = "test-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2335
remotePort = 2334
__EOF__

write_tmp_config frps.toml <<__EOF__
bindPort = 2333
log.level = "error"
__EOF__

cargo run -- example-config example.com >tmp/rtunnel.toml
chmod 600 tmp/rtunnel.toml
