FROM rust:1.98.1-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release
CMD ["cargo", "run", "--release"]

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/settings.yaml /
COPY --from=builder /app/private-key.pem /
COPY --from=builder /app/target/release/moidc /
CMD ["./moidc"]
