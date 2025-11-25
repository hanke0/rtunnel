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

download_zip() {
    echo "Downloading $2"
    wget -q -O /tmp/a.zip "$2"
    rm -rf /tmp/tarball
    mkdir /tmp/tarball
    unzip /tmp/a.zip -d /tmp/tarball
    rm -rf /tmp/a.zip
    mkdir -p tmp
    find /tmp/tarball -name "$1" -exec echo cp -f {} tmp/ \; -exec cp -f {} tmp/ \;
    rm -rf /tmp/tarball
}

case $(uname -o)_$(uname -m) in
*Linux_x86_64)
    FRPURL="https://github.com/fatedier/frp/releases/download/v0.65.0/frp_0.65.0_linux_amd64.tar.gz"
    RATHOLEURL="https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip"
    ;;
Darwin_arm64)
    FRPURL="https://github.com/fatedier/frp/releases/download/v0.65.0/frp_0.65.0_darwin_arm64.tar.gz"
    ;;
*)
    echo "unsupported architecture"
    exit 1
    ;;
esac

if [ "$1" != "cfg" ]; then
    download_tar "frp[cs]" "$FRPURL"
    download_tar "rathole" "$RATHOLEURL"
fi

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

write_tmp_config frpc-tls.toml <<__EOF__
serverAddr = "127.0.0.1"
serverPort = 2333
log.level = "error"
transport.tls.enable = true
transport.tls.certFile = "tmp/client.crt"
transport.tls.keyFile = "tmp/client.key"
transport.tls.trustedCaFile = "tmp/client_ca.crt"
transport.tls.serverName = "example.com"


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

write_tmp_config frps-tls.toml <<__EOF__
bindPort = 2333
log.level = "error"
transport.tls.force = true
transport.tls.certFile = "tmp/server.crt"
transport.tls.keyFile = "tmp/server.key"
transport.tls.trustedCaFile = "tmp/server_ca.crt"
__EOF__

write_tmp_config rathole.toml <<__EOF__
[client]
remote_addr = "127.0.0.1:2333"
default_token = "123"

[client.transport]
type = "tls"
[client.transport.tls]
trusted_root = "tmp/rootCA.crt"
hostname = "localhost"

[client.services.foo1]
local_addr = "127.0.0.1:2335"


[server]
bind_addr = "127.0.0.1:2333"
default_token = "123"

[server.transport]
type = "tls"
[server.transport.tls]
pkcs12 = "tmp/identity.pfx"
pkcs12_password = "1234"

[server.services.foo1]
bind_addr = "127.0.0.1:2334"
__EOF__


cargo run --quiet -- example-config example.com >tmp/rtunnel.toml
cargo run --quiet -- example-config --kind tls example.com >tmp/rtunnel-tls.toml
cargo run --quiet -- self-signed-cert example.com -o tmp
./benchmark/create-self-signed.sh tmp
chmod 600 tmp/rtunnel.toml tmp/rtunnel-tls.toml
chmod 600 tmp/client.key tmp/server.key
