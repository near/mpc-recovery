FROM rust:latest as builder
WORKDIR /usr/src/app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler libprotobuf-dev
RUN echo "fn main() {}" > dummy.rs
COPY mpc-recovery/Cargo.toml Cargo.toml
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release
COPY . .
RUN sed -i 's#"integration-tests",##' Cargo.toml
RUN cargo build --release --package mpc-recovery

FROM debian:bookworm-slim as runtime
RUN apt-get update && apt-get install --assume-yes libssl-dev ca-certificates curl
RUN update-ca-certificates
COPY --from=builder /usr/src/app/target/release/mpc-recovery /usr/local/bin/mpc-recovery
WORKDIR /usr/local/bin

ENTRYPOINT [ "mpc-recovery" ]