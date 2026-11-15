# syntax=docker/dockerfile:1
FROM rust:1.88-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/slopshop-backend /usr/local/bin/slopshop-backend
COPY service.txt ./service.txt
ENV SLOP_BIND=0.0.0.0:8080
ENV SLOP_DB=/data/slopshop.db
ENV SLOP_RESOURCE_DIR=/app
EXPOSE 8080
VOLUME ["/data"]
USER nobody
CMD ["slopshop-backend"]
