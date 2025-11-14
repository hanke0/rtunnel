#!/bin/bash

set -e

cargo fmt
cargo clippy --no-deps --fix --allow-dirty -- -D warnings
