# syntax=docker/dockerfile:1.6
# Брокер на debian-slim: кроме nats-server нужен только bash для
# healthcheck'а (compose проверяет /healthz через /dev/tcp, потому что
# curl/wget в slim-образе нет).
FROM debian:bookworm-slim

ARG NATS_VERSION=v2.12.6
# SHA256 из SHA256SUMS официального релиза; при смене версии меняется вместе с ней.
ARG NATS_SHA256=77fe7dd69ff5144126026b78355900be0ab0bb4339dc61a7621dcc9b9e9d07a6

ADD --checksum=sha256:${NATS_SHA256} \
    https://github.com/nats-io/nats-server/releases/download/${NATS_VERSION}/nats-server-${NATS_VERSION}-linux-amd64.tar.gz \
    /tmp/nats-server.tgz

RUN tar -xzf /tmp/nats-server.tgz -C /tmp \
    && install -m 0755 "/tmp/nats-server-${NATS_VERSION}-linux-amd64/nats-server" /usr/local/bin/nats-server \
    && rm -rf /tmp/nats-server*

CMD ["nats-server"]
