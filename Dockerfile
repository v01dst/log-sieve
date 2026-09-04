FROM rust:1.96-slim AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=build /src/target/release/log-sieve /usr/local/bin/log-sieve
ENTRYPOINT ["log-sieve"]
