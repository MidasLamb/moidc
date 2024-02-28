FROM rust:1.72.1
WORKDIR /usr/src/moidc
COPY . .
RUN cargo build --release
CMD ["cargo", "run", "--release"]
