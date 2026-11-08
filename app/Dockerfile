# version : 0.10
# created by : JK and CF
# last edited : 01/11/2026
# Name : bro-backup (Dockerfile)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
#
# One image with everything inside: the app, restic, rest-server and dumbpipe (iroh).
# Binaries are pinned by version and SHA256 checksum.
# Build from the repository root: docker build -f app/Dockerfile .

FROM python:3.13-alpine

ARG TARGETARCH
ARG RESTIC_VERSION=0.18.1
ARG REST_SERVER_VERSION=0.14.0
ARG DUMBPIPE_VERSION=0.40.1

RUN apk add --no-cache ca-certificates tzdata && \
    set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) RA=amd64; DA=x86_64; \
             RESTIC_SHA=680838f19d67151adba227e1570cdd8af12c19cf1735783ed1ba928bc41f363d; \
             RS_SHA=4c9c95bc079a0334e81fad379b19dc5c3353c71c2c88d652cafce2081c2b1c66; \
             DP_SHA=66aee1e249890ee63678dfc8f18ce3671e691673c83bbd72bf9a54c4d32da85c ;; \
      arm64) RA=arm64; DA=aarch64; \
             RESTIC_SHA=87f53fddde38764095e9c058a3b31834052c37e5826d2acf34e18923c006bd45; \
             RS_SHA=cef139cbe8b27b16bda731d17f093b0aa466b8c60b136c12d78b6f2bff3daf22; \
             DP_SHA=1529c49598ac15d9413bf7f29a09c04cf2f5dc3af1b9080a1b50855a77846c47 ;; \
      *) echo "Architecture ${TARGETARCH} not supported"; exit 1 ;; \
    esac; \
    cd /tmp; \
    wget -q -O restic.bz2 "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_${RA}.bz2"; \
    echo "${RESTIC_SHA}  restic.bz2" | sha256sum -c -; \
    bunzip2 restic.bz2; install -m 755 restic /usr/local/bin/restic; \
    wget -q -O rs.tgz "https://github.com/restic/rest-server/releases/download/v${REST_SERVER_VERSION}/rest-server_${REST_SERVER_VERSION}_linux_${RA}.tar.gz"; \
    echo "${RS_SHA}  rs.tgz" | sha256sum -c -; \
    tar xzf rs.tgz; install -m 755 rest-server_*/rest-server /usr/local/bin/rest-server; \
    wget -q -O dp.tgz "https://github.com/n0-computer/dumbpipe/releases/download/v${DUMBPIPE_VERSION}/dumbpipe-v${DUMBPIPE_VERSION}-linux-${DA}.tar.gz"; \
    echo "${DP_SHA}  dp.tgz" | sha256sum -c -; \
    tar xzf dp.tgz; install -m 755 dumbpipe /usr/local/bin/dumbpipe; \
    rm -rf /tmp/*; \
    restic version && dumbpipe --version

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/main.py app/THIRD_PARTY_NOTICES.md LICENSE ./
COPY app/bro ./bro
COPY app/templates ./templates
COPY app/static ./static

# Set TZ in your compose file so the nightly backup runs at your local time.
ENV PYTHONUNBUFFERED=1 TZ=UTC DATA_DIR=/data NAS_DIR=/nas

EXPOSE 8484
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8484/healthz', timeout=3)"

# Runs as root in the container so restic can read every file. /nas is mounted read-only.
CMD ["python", "main.py"]
