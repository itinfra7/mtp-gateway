# Ubuntu 24.04와 Rust 배포 압축본을 내용 해시로 고정한다.
FROM docker.io/library/ubuntu:24.04@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc AS builder
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config && rm -rf /var/lib/apt/lists/*
ARG RUST_VERSION=1.98.1
ARG RUST_SHA256=5326b36c53de11d148c8f8dab6553a3d1006c2cfd32123683073fad3c302605b
RUN curl -fsSLo /tmp/rust.tar.xz https://static.rust-lang.org/dist/rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.xz && echo "${RUST_SHA256}  /tmp/rust.tar.xz" | sha256sum -c - && tar -xJf /tmp/rust.tar.xz -C /tmp && /tmp/rust-${RUST_VERSION}-x86_64-unknown-linux-gnu/install.sh --prefix=/opt/rust --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu --disable-ldconfig && rm -rf /tmp/rust*
RUN mkdir -p /build /home/builder && chown 65532:65532 /build /home/builder
ENV PATH=/opt/rust/bin:$PATH HOME=/home/builder CARGO_HOME=/home/builder/cargo
WORKDIR /build
COPY --chown=65532:65532 . .
USER 65532:65532
RUN cargo build --release --workspace --locked && cargo test --workspace --locked --no-run
FROM builder AS verification
ENTRYPOINT ["/opt/rust/bin/cargo", "test", "--workspace", "--locked"]
FROM docker.io/library/ubuntu:24.04@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc AS runtime
COPY --from=builder /build/target/release/mtp-gateway /usr/local/bin/mtp-gateway
COPY --from=builder /build/target/release/mtp-test-peer /usr/local/bin/mtp-test-peer
USER 65532:65532
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/mtp-gateway"]
CMD ["serve", "--config", "/etc/mtp-gateway/gateway.toml"]
