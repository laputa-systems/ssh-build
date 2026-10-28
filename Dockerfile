# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

# Pinned Alpine line (same digest as git-minimal-musl-static at preflight).
FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS build

RUN apk add --no-cache \
        binutils=2.45.1-r1 \
        gcc=15.2.0-r5 \
        make=4.4.1-r4 \
        musl-dev=1.2.6-r3 \
        linux-headers=7.0.0-r1 \
        zlib-dev=1.3.2-r1 \
        zlib-static=1.3.2-r1 \
        file

RUN case "$(apk --print-arch)" in \
        aarch64|x86_64) ;; \
        *) echo "unsupported Alpine architecture: $(apk --print-arch)" >&2; exit 1 ;; \
    esac

WORKDIR /src

ARG OPENSSH_VERSION
ARG OPENSSH_SHA256
RUN test -n "$OPENSSH_VERSION" && test -n "$OPENSSH_SHA256"

# BuildKit fetches the official portable release archive. Its SHA-256 keeps
# the source immutable without putting a downloader or CA bundle in the image.
ADD --checksum=sha256:${OPENSSH_SHA256} \
    --unpack=true \
    https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz /src/

WORKDIR /src/openssh-${OPENSSH_VERSION}

RUN set -eux; \
    ./configure --without-openssl --with-ldflags="-static" --disable-strip; \
    make -j"$(getconf _NPROCESSORS_ONLN)" ssh ssh-keygen ssh-agent ssh-add sftp scp; \
    ./ssh -V 2>&1; \
    strip ssh ssh-keygen ssh-agent ssh-add sftp scp; \
    mkdir /out; \
    cp -a ssh ssh-keygen ssh-agent ssh-add sftp scp /out/; \
    for b in ssh ssh-keygen ssh-agent ssh-add sftp scp; do \
        test -x "/out/$b"; \
    done

COPY scripts/qualify-binaries.sh /tmp/qualify-binaries.sh

RUN sh /tmp/qualify-binaries.sh /out \
    && rm /tmp/qualify-binaries.sh

FROM scratch AS artifacts

COPY --from=build /out/ /
