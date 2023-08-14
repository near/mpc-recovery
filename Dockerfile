FROM rust:latest as builder
RUN rustc --version --verbose
WORKDIR /usr/src/app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler libprotobuf-dev
RUN echo "fn main() {}" > dummy.rs
COPY node/Cargo.toml Cargo.toml
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release
COPY . .
RUN sed -i 's#"mpc-recovery",##' Cargo.toml
RUN sed -i 's#"contract",##' Cargo.toml
RUN sed -i 's#"integration-tests"##' Cargo.toml
RUN cargo build --package mpc-recovery-node

FROM debian:stable-slim as runtime
RUN apt-get update && apt-get install --assume-yes libssl-dev ca-certificates curl
RUN update-ca-certificates
COPY --from=builder /usr/src/app/target/debug/mpc-recovery-node /usr/local/bin/mpc-recovery-node
WORKDIR /usr/local/bin

ENTRYPOINT [ "mpc-recovery-node" ]
