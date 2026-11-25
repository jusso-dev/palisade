# Linux development image for Palisade (#29). Builds and tests every
# portable crate, and checks the Windows-only code with `cargo check
# --target x86_64-pc-windows-gnu`. See docs/dev/unix.md.
#
# The base image is the official Rust image for the toolchain pinned in
# rust-toolchain.toml, pinned by digest (multi-architecture: x86_64 and
# arm64 hosts). `cargo xtask` tests check that the toolchain and every tool
# version below match rust-toolchain.toml and xtask/src/ci.rs.

# rust:1.100.0-slim-trixie
FROM rust@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2

ARG RUST_TOOLCHAIN=1.100.0
ARG FUZZ_TOOLCHAIN=nightly-2026-11-20

# System packages: Git, a C toolchain for build scripts, the MinGW-w64 linker
# for the Windows GNU target, Postgres client tools for the server tests,
# and ShellCheck for the scripts under .github and .githooks.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential ca-certificates curl git gcc-mingw-w64-x86-64 \
        pkg-config postgresql-client shellcheck \
    && rm -rf /var/lib/apt/lists/*

# The pinned toolchain with its components and targets
# (rust-toolchain.toml), plus the Windows GNU target for local checks, and
# the pinned nightly that cargo-fuzz needs.
RUN rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal \
        --component rustfmt,clippy,llvm-tools-preview \
        --target x86_64-pc-windows-msvc,aarch64-pc-windows-msvc,x86_64-unknown-linux-gnu,x86_64-pc-windows-gnu \
    && rustup default "$RUST_TOOLCHAIN" \
    && rustup toolchain install "$FUZZ_TOOLCHAIN" --profile minimal

# The cargo tools CI uses, at the versions CI installs (xtask/src/ci.rs),
# and the documentation tools (#27). Built from source with `--locked`, so
# no prebuilt binary from outside the crate registry is trusted.
RUN cargo install --locked \
        cargo-nextest@0.9.152 \
        cargo-deny@0.22.0 \
        cargo-audit@0.23.0 \
        cargo-vet@0.10.3 \
        cargo-hack@0.6.46 \
        cargo-llvm-cov@0.9.2 \
        zizmor@1.33.1 \
        typos-cli@1.52.2 \
        mdbook@0.5.2 \
        lychee@0.24.2 \
    && cargo +"$FUZZ_TOOLCHAIN" install --locked cargo-fuzz@0.13.2 \
    && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# Optional: `cargo xwin check --target x86_64-pc-windows-msvc` checks the
# MSVC target too. It downloads the Windows SDK and C runtime headers on
# first use, under their own licence, which you must accept; so it is not
# installed by default. Build with `--build-arg WITH_XWIN=1` to add it.
ARG WITH_XWIN=0
RUN if [ "$WITH_XWIN" = "1" ]; then \
        cargo install --locked cargo-xwin@0.24.1 \
        && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"; \
    fi

# A non-root user, matching the host user's UID in most setups.
RUN useradd --create-home --uid 1000 --shell /bin/bash dev \
    && chown -R dev "$CARGO_HOME" "$RUSTUP_HOME"
USER dev
