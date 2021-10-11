#!/bin/bash -ex
cargo clean
cargo test test_loopback --target x86_64-unknown-linux-gnu --verbose
