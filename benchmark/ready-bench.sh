#!/bin/bash

download_tar() {
    echo "Downloading $2"
    wget -q -O /tmp/a.tar.gz "$2"
    rm -rf /tmp/tarball
    mkdir /tmp/tarball
    tar -xf /tmp/a.tar.gz -C /tmp/tarball
    rm -rf /tmp/a.tar.gz
    mkdir -p "tmp/$3"
    find /tmp/tarball -name "$1" -exec echo cp -f {} tmp/ \; -exec cp -f {} "tmp/$3" \;
    rm -rf /tmp/tarball
}

download_zip() {
    echo "Downloading $2"
    wget -q -O /tmp/a.zip "$2"
    rm -rf /tmp/tarball
    mkdir /tmp/tarball
    unzip /tmp/a.zip -d /tmp/tarball
    rm -rf /tmp/a.zip
    mkdir -p "tmp/$3"
    find /tmp/tarball -name "$1" -exec echo cp -f {} tmp/ \; -exec cp -f {} "tmp/$3" \;
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
    download_tar "frp[cs]" "$FRPURL" frp
    download_zip "rathole" "$RATHOLEURL" rathole
fi

write_tmp_config() {
    local dst
    dst="tmp/$1"
    if [ ! -d "$dst" ]; then
        mkdir -p "$dst"
    fi
    echo "write content to file: $dst/$2"
    cat - >"$dst/$2"
}

write_tmp_config frp frpc-tcp.toml <<__EOF__
serverAddr = "127.0.0.1"
serverPort = 2333
log.level = "warn"
log.disablePrintColor = true

[[proxies]]
name = "test-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2335
remotePort = 2334
__EOF__

write_tmp_config frp frpc-tls.toml <<__EOF__
serverAddr = "127.0.0.1"
serverPort = 2333
log.level = "warn"
log.disablePrintColor = true
transport.tls.enable = true
transport.tls.certFile = "tmp/frp/client.crt"
transport.tls.keyFile = "tmp/frp/client.key"
transport.tls.trustedCaFile = "tmp/frp/client_ca.crt"
transport.tls.serverName = "example.com"


[[proxies]]
name = "test-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2335
remotePort = 2334

__EOF__

write_tmp_config frp frps-tcp.toml <<__EOF__
bindPort = 2333
log.level = "warn"
transport.maxPoolCount = 20
__EOF__

write_tmp_config frp frps-tls.toml <<__EOF__
bindPort = 2333
log.level = "warn"
transport.tls.force = true
transport.tls.certFile = "tmp/frp/server.crt"
transport.tls.keyFile = "tmp/frp/server.key"
transport.tls.trustedCaFile = "tmp/frp/server_ca.crt"
transport.maxPoolCount = 20
__EOF__

write_tmp_config rathole rathole-tcp.toml <<__EOF__
[client]
remote_addr = "127.0.0.1:2333"
default_token = "123"

[client.services.foo1]
local_addr = "127.0.0.1:2335"


[server]
bind_addr = "127.0.0.1:2333"
default_token = "123"

[server.services.foo1]
bind_addr = "127.0.0.1:2334"
__EOF__

write_tmp_config rathole rathole-tls.toml <<__EOF__
[client]
remote_addr = "127.0.0.1:2333"
default_token = "123"

[client.transport]
type = "tls"
[client.transport.tls]
trusted_root = "tmp/rathole/rootCA.crt"
hostname = "localhost"

[client.services.foo1]
local_addr = "127.0.0.1:2335"


[server]
bind_addr = "127.0.0.1:2333"
default_token = "123"

[server.transport]
type = "tls"
[server.transport.tls]
pkcs12 = "tmp/rathole/identity.pfx"
pkcs12_password = "1234"

[server.services.foo1]
bind_addr = "127.0.0.1:2334"
__EOF__

mkdir -p tmp/rtunnel
cargo run --quiet -- example-config --type plain-tcp example.com >tmp/rtunnel/rtunnel-tcp.toml
cargo run --quiet -- example-config --type tls-tcp example.com >tmp/rtunnel/rtunnel-tls.toml
cargo run --quiet -- example-config --type quic example.com >tmp/rtunnel/rtunnel-quic.toml
cargo run --quiet -- self-signed-cert example.com -o tmp/frp
mkdir -p tmp/frp
./benchmark/create-self-signed.sh tmp/rathole
chmod 600 tmp/frp/client.key tmp/frp/server.key
chmod 600 tmp/rtunnel/*.toml
