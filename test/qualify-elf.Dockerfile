# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf
FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache binutils=2.45.1-r1 gcc=15.2.0-r5 musl-dev=1.2.6-r3 file

COPY scripts/qualify-binaries.sh /qualify.sh
RUN printf 'int main(void) { return 0; }\n' > /t.c
RUN set -eu; \
    build() { mkdir -p "/fx/$1"; gcc -static-pie $2 /t.c -o "/fx/$1/fixture"; }; \
    build good "-Wl,-z,relro -Wl,-z,noexecstack"; \
    build exec_stack "-Wl,-z,relro -Wl,-z,execstack"; \
    build no_relro "-Wl,-z,norelro -Wl,-z,noexecstack"; \
    export EXPECT_ARCH="$(uname -m)" QUALIFY_BINS=fixture; \
    sh /qualify.sh /fx/good linux; \
    for bad in exec_stack:"non-executable stack" no_relro:"GNU_RELRO"; do \
        dir="${bad%%:*}"; want="${bad#*:}"; \
        if sh /qualify.sh "/fx/$dir" linux > "/fx/$dir.out" 2>&1; then echo "$dir passed qualification" >&2; exit 1; fi; \
        grep -q "FAIL: fixture: .*$want" "/fx/$dir.out" || { cat "/fx/$dir.out" >&2; echo "$dir failed for the wrong reason" >&2; exit 1; }; \
    done; \
    echo "qualifier rejects executable stacks and missing RELRO"
