FROM rust:1.95.0-alpine3.23@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2 AS builder

RUN apk add --no-cache build-base ca-certificates musl-dev

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --locked -p bowline
RUN cargo build --release --locked -p bowline-gateway --example echo_upstream
RUN install -d -o 65532 -g 65532 /runtime/config/ledger \
    && touch /runtime/config/ledger/.bowline-volume \
    && chown 65532:65532 /runtime/config/ledger/.bowline-volume

FROM scratch AS echo-upstream

COPY --from=builder --chown=65532:65532 /src/target/release/examples/echo_upstream /echo_upstream

EXPOSE 9999
USER 65532:65532
ENTRYPOINT ["/echo_upstream"]
CMD ["0.0.0.0:9999"]

FROM scratch AS bowline

ARG VCS_REF=unknown
ARG VERSION=0.1.0-dev
LABEL org.opencontainers.image.title="Bowline" \
      org.opencontainers.image.description="Shadow-mode intelligence allocation evidence gateway" \
      org.opencontainers.image.source="https://github.com/Mindpool-Labs/bowline" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=65532:65532 /src/target/release/bowline /bowline
COPY --from=builder --chown=65532:65532 /runtime/config /config

EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/bowline", "health", "--url", "http://127.0.0.1:8080/health/ready"]
ENTRYPOINT ["/bowline"]
