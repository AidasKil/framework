#!/usr/bin/env bash

# You can use this to install non-Rust dependencies on Debian-based distributions.
install_dependencies_on_debian() {
    apt-get install       \
        cmake             \
        libssl-dev        \
        moreutils         \
        pkg-config        \
        silversearcher-ag \
        zlib1g-dev
}

set -o errexit
shopt -s extglob globstar

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

readonly script_dir="$(dirname "$0")"

# Refer to Bash explicitly because that's what rustup does:
# https://github.com/rust-lang/rustup/blob/1db9dc9d26682fc71eb05a0d1ae5d81ef3f1c4ac/rustup-init.sh#L1
curl                     \
    --fail               \
    --proto =https       \
    --show-error         \
    --silent             \
    --tlsv1.2            \
    https://sh.rustup.rs |
    sponge               |
    bash -s -- --no-modify-path -y

rustup component add clippy rustfmt

cargo install cargo-tarpaulin

# cargo-fmt only formats crates listed in workspace.members in Cargo.toml.
rustfmt --check -- "$script_dir"/../!(lighthouse|target)/**/*.rs

"$script_dir"/clippy.sh

# Past versions of Tarpaulin would sometimes cause segmentation faults in
# multithreaded tests. Tarpaulin exits successfully (with zero status) when that
# happens. We work around that by searching Tarpaulin's output for error
# messages and making the build fail if we find any.
! "$script_dir"/tarpaulin.sh |& ag --passthrough Error
