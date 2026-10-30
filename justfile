# herdr-auth-proxy developer tasks

default: build

build:
    cargo build

test:
    cargo test

clippy:
    cargo clippy --all-targets -- -D warnings

fmt:
    cargo fmt --all
