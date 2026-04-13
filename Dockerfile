FROM rust:1.89.0-alpine3.20 AS builder

WORKDIR /usr/src/kasia-indexer

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static curl protobuf

COPY . .

RUN cargo build --release -p indexer

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata openssh-client \
    && addgroup -S indexer \
    && adduser -S -G indexer indexer

WORKDIR /app

COPY --from=builder /usr/src/kasia-indexer/target/release/indexer /app/indexer

RUN mkdir -p /data /app/secrets \
    && chown -R indexer:indexer /app /data

USER indexer

ENV KASIA_INDEXER_DB_ROOT=/data

EXPOSE 8080

CMD ["./indexer"]
