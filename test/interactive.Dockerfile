# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf
#
# Images for test/e2e-interactive.sh. The script stages a small build context (ish/ish from
# scripts/fetch-ish.sh, oxish/ with the server binaries, client/ with the client under test,
# interactive-driver.py) and derives the TMUX_*, LIBEVENT_* and NCURSES_* build arguments from
# tmux.lock.json:
#   tmux-build        static tmux and tput from the pinned source tarballs
#   server-oxish      the login-mode server under test plus ish, tmux, tput, terminfo
#   server-standin    STAND-IN: Alpine's OpenSSH sshd instead of oxish-server, same account and tools
#   client            the client under test and the PTY driver (Python image pinned by digest)
#
# tmux comes from source because no static, checksummed tmux binary is published: BuildKit fetches the
# upstream release tarballs and verifies each SHA-256 (the same way the OpenSSH Dockerfile does), the
# toolchain packages are pinned to exact Alpine versions, and the result links libevent and ncurses
# statically, so the server image needs no tmux or ncurses package. tput and a terminfo database come
# from the same ncurses build.

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS tmux-build

RUN apk add --no-cache \
        binutils=2.45.1-r1 \
        gcc=15.2.0-r5 \
        make=4.4.1-r4 \
        musl-dev=1.2.6-r3 \
        linux-headers=7.0.0-r1 \
        pkgconf=2.5.1-r0 \
        byacc=20260126-r0

ARG TMUX_URL
ARG TMUX_SHA256
ARG LIBEVENT_URL
ARG LIBEVENT_SHA256
ARG NCURSES_URL
ARG NCURSES_SHA256
RUN test -n "$TMUX_URL" && test -n "$TMUX_SHA256" && test -n "$LIBEVENT_URL" \
    && test -n "$LIBEVENT_SHA256" && test -n "$NCURSES_URL" && test -n "$NCURSES_SHA256"

ADD --checksum=sha256:${NCURSES_SHA256} ${NCURSES_URL} /src/ncurses.tar.gz
ADD --checksum=sha256:${LIBEVENT_SHA256} ${LIBEVENT_URL} /src/libevent.tar.gz
ADD --checksum=sha256:${TMUX_SHA256} ${TMUX_URL} /src/tmux.tar.gz

WORKDIR /src
RUN set -eux; \
    mkdir ncurses libevent tmux; \
    tar -xzf ncurses.tar.gz -C ncurses --strip-components=1; \
    tar -xzf libevent.tar.gz -C libevent --strip-components=1; \
    tar -xzf tmux.tar.gz -C tmux --strip-components=1

ENV PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig
RUN set -eux; cd ncurses; \
    ./configure --prefix=/opt/deps --without-shared --with-normal --without-debug --without-ada \
        --without-cxx --without-cxx-binding --without-manpages --without-tests --enable-widec \
        --enable-pc-files --with-pkg-config-libdir=/opt/deps/lib/pkgconfig --disable-stripping \
        --with-terminfo-dirs=/usr/share/terminfo --with-default-terminfo-dir=/usr/share/terminfo; \
    make -j"$(getconf _NPROCESSORS_ONLN)"; \
    make install
RUN set -eux; cd libevent; \
    ./configure --prefix=/opt/deps --disable-shared --enable-static --disable-openssl \
        --disable-samples --disable-libevent-regress; \
    make -j"$(getconf _NPROCESSORS_ONLN)"; \
    make install
RUN set -eux; cd tmux; \
    PKG_CONFIG='pkg-config --static' ./configure --prefix=/opt/tmux --enable-static; \
    make -j"$(getconf _NPROCESSORS_ONLN)"; \
    strip tmux; \
    mkdir -p /out/usr/local/bin; \
    cp tmux /out/usr/local/bin/tmux; \
    cp /opt/deps/bin/tput /out/usr/local/bin/tput; \
    strip /out/usr/local/bin/tput; \
    mkdir -p /out/usr/share; \
    cp -a /usr/share/terminfo /out/usr/share/terminfo; \
    ! readelf -l /out/usr/local/bin/tmux | grep -q INTERP; \
    ! readelf -l /out/usr/local/bin/tput | grep -q INTERP; \
    /out/usr/local/bin/tmux -V

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS server-base

COPY --from=tmux-build /out/ /
COPY ish/ish /usr/local/bin/ish
# One account whose login shell is ish; the password field is "*" (not "!") so sshd accepts keys.
RUN set -eux; \
    echo /usr/local/bin/ish >> /etc/shells; \
    ln -s /usr/local/bin/tmux /usr/bin/tmux; \
    ln -s /usr/local/bin/tput /usr/bin/tput; \
    adduser -D -s /usr/local/bin/ish -h /home/work work; \
    sed -i 's/^work:!/work:*/' /etc/shadow; \
    printf 'set -g mouse on\nset -g focus-events on\nset -g status-interval 1\n' > /home/work/.tmux.conf; \
    chown work /home/work/.tmux.conf; \
    mkdir -p /srv/e2e

FROM server-base AS server-standin
# STAND-IN only: remove together with the standin mode of test/e2e-interactive.sh.
RUN apk add --no-cache openssh-server=10.3_p1-r2
CMD ["/bin/sh", "/srv/e2e/entry.sh"]

FROM server-base AS server-oxish
COPY oxish/ /usr/local/bin/
CMD ["/bin/sh", "/srv/e2e/entry.sh"]

FROM python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67 AS client
COPY client/ /opt/client/
COPY interactive-driver.py /opt/driver/interactive-driver.py
WORKDIR /opt/driver
