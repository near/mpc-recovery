FROM rust:latest as builder
WORKDIR /usr/src/app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler libprotobuf-dev
COPY ./targe[t]/docker-cache.tg[z] ./target/docker-cache.tgz
RUN [ -f ./target/docker-cache.tgz ] \
    && tar -xzC / -f ./target/docker-cache.tgz \
    && rm ./target/docker-cache.tgz \
    || true
COPY . .
RUN rm ./target/docker-cache.tgz
RUN CARGO_INCREMENTAL=0 cargo build --release --package mpc-recovery
# todo! prune unused artifacts (ex: now-unused deps, previous builds)
RUN mkdir -p target/.stamp \
    && find /usr/src/app/target/release -type f | sort > target/.stamp/target \
    && find /usr/local/cargo/bin -type f | sort > target/.stamp/cargo-bin \
    && find /usr/local/cargo/git/db -type f | sort > target/.stamp/cargo-git-db \
    && find /usr/local/cargo/registry/cache -type f | sort > target/.stamp/cargo-registry-cache \
    && find /usr/local/cargo/registry/index -type f | sort > target/.stamp/cargo-registry-index \
    && touch /usr/local/cargo/.crates.toml /usr/local/cargo/.crates2.json \
    && sha256sum /usr/local/cargo/.crates.toml > target/.stamp/cargo-crates-toml \
    && sha256sum /usr/local/cargo/.crates2.json > target/.stamp/cargo-crates2-json

FROM scratch as retrieve-stamp
COPY --from=builder /usr/src/app/target/.stamp /

FROM scratch as export-artifacts
COPY --from=builder /usr/src/app/target /usr/src/app/target
COPY --from=builder /usr/local/cargo/bin /usr/local/cargo/bin
COPY --from=builder /usr/local/cargo/git /usr/local/cargo/git
COPY --from=builder /usr/local/cargo/.crates.toml /usr/local/cargo/.crates.toml
COPY --from=builder /usr/local/cargo/.crates2.json /usr/local/cargo/.crates2.json
COPY --from=builder /usr/local/cargo/registry/cache /usr/local/cargo/registry/cache
COPY --from=builder /usr/local/cargo/registry/index /usr/local/cargo/registry/index

FROM debian:bullseye-slim as runtime
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    libssl-dev ca-certificates curl
RUN update-ca-certificates
COPY --from=builder /usr/src/app/target/release/mpc-recovery /usr/local/bin/mpc-recovery
WORKDIR /usr/local/bin

ENTRYPOINT [ "mpc-recovery" ]
