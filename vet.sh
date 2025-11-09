#!/bin/bash

set -e

cargo fmt
cargo fix --allow-dirty --all-features --workspace
cargo clippy --no-deps --fix --allow-dirty -- -D warnings
cargo check --all-features --workspace
