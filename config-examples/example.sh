#!/bin/bash

gen() {
    cargo run --quiet -- example-config --type $1 example.com >config-examples/$1.toml
}

gen plain-tcp
gen tls-tcp
gen quic
