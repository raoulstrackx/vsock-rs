#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${repo_root}

cargo test
cargo test --no-default-features
cargo test --no-default-features --features "random_port"
