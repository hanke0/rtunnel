#!/bin/bash

set -e

cargo fmt
cargo fix --allow-dirty --all-targets
cargo clippy --no-deps --fix --allow-dirty --all-targets -- -D warnings
