#!/bin/bash

set -e

cargo fmt
cargo clippy --no-deps --fix --allow-dirty --all-targets -- -D warnings
