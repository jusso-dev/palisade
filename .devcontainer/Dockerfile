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
# The MSRV (`rust-version` in the root Cargo.toml), for the `msrv` step of
# `cargo xtask ci`.
ARG MSRV_TOOLCHAIN=1.94.0
# actionlint, for the `workflow-lint` step, as the CI job installs it: the
# release archive, checked against its published SHA-256.
ARG ACTIONLINT_VERSION=1.7.12
ARG ACTIONLINT_SHA256_AMD64=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ARG ACTIONLINT_SHA256_ARM64=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6

# System packages: Git, a C toolchain for build scripts, the MinGW-w64 linker
# for the Windows GNU target, Postgres client tools for the server tests,
# ShellCheck for the scripts under .github and .githooks, and procps for
# `kill`, which the agent and server tests run to send real signals (the
# slim base image has none). Versions come from the Debian release of the
# base image, which is pinned by digest.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential ca-certificates curl git gcc-mingw-w64-x86-64 \
        pkg-config postgresql-client procps shellcheck \
    && rm -rf /var/lib/apt/lists/*

# The pinned toolchain with its components and targets
# (rust-toolchain.toml), plus the Windows GNU target for local checks, and
# the pinned nightly that cargo-fuzz needs.
RUN rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal \
        --component rustfmt,clippy,llvm-tools-preview \
        --target x86_64-pc-windows-msvc,aarch64-pc-windows-msvc,x86_64-unknown-linux-gnu,x86_64-pc-windows-gnu \
    && rustup default "$RUST_TOOLCHAIN" \
    && rustup toolchain install "$FUZZ_TOOLCHAIN" --profile minimal \
    && rustup toolchain install "$MSRV_TOOLCHAIN" --profile minimal

RUN case "$(dpkg --print-architecture)" in \
        amd64) arch=amd64; sum="$ACTIONLINT_SHA256_AMD64" ;; \
        arm64) arch=arm64; sum="$ACTIONLINT_SHA256_ARM64" ;; \
        *) echo "no actionlint build for this architecture" >&2; exit 1 ;; \
    esac \
    && archive="actionlint_${ACTIONLINT_VERSION}_linux_${arch}.tar.gz" \
    && curl -sSfL -o "/tmp/$archive" \
        "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/$archive" \
    && echo "$sum  /tmp/$archive" | sha256sum --check --strict \
    && tar -xzf "/tmp/$archive" -C /usr/local/bin actionlint \
    && rm "/tmp/$archive"

# The cargo tools CI uses, at the versions CI installs (xtask/src/ci.rs),
# and the documentation tools (#27), built from source with `--locked`.
# actionlint (above) is the one prebuilt binary, checked against its
# published SHA-256, as CI does.
RUN cargo install --locked \
        cargo-nextest@0.9.152 \
        cargo-deny@0.22.0 \
        cargo-audit@0.23.0 \
        cargo-vet@0.10.3 \
        cargo-hack@0.6.46 \
        cargo-llvm-cov@0.9.2 \
        cargo-insta@1.49.0 \
        zizmor@1.33.1 \
        typos-cli@1.52.2 \
        mdbook@0.5.2 \
        mdbook-mermaid-ssr@0.3.0 \
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

# A non-root user, matching the host user's UID in most setups. The build
# output directory is created here, owned by that user, because compose.yaml
# mounts a named volume over it, and a new named volume copies the owner of
# the directory it is mounted on (root, if the directory did not exist).
RUN useradd --create-home --uid 1000 --shell /bin/bash dev \
    && mkdir -p /workspaces/palisade/target \
    && chown -R dev "$CARGO_HOME" "$RUSTUP_HOME" /workspaces/palisade
USER dev
