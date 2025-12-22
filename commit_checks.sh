#!/bin/bash

echo "running fmt check"
cargo fmt --all -- --check

echo "running clippy check"
cargo clippy -- -D warnings

echo "running tests"
cargo test --verbose

echo "building"
cargo build --verbose

