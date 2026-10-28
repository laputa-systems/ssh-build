# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf
#
# Run test/e2e-git.sh on the Linux bytes as an unprivileged user inside a build step (BuildKit
# runs the step natively for the chosen --platform). Inputs are the built client and server
# directories and the git-build directory fetched by scripts/fetch-git-build.sh:
#   docker buildx build --platform linux/arm64 -f test/linux-e2e.Dockerfile \
#     --build-arg SSH_DIR=dist/linux-aarch64/bin --build-arg OXISH_DIR=dist/oxish-linux-aarch64/bin \
#     --build-arg GIT_DIR=<fetched git-build dir relative to the repository> .
FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG SSH_DIR
ARG OXISH_DIR
ARG GIT_DIR
RUN adduser -D -h /home/tester tester && mkdir /w && chown tester /w
COPY --chown=tester ${SSH_DIR} /w/in/ssh
COPY --chown=tester ${OXISH_DIR} /w/in/oxish
COPY --chown=tester ${GIT_DIR} /w/in/git
COPY --chown=tester test/e2e-git.sh /w/test/e2e-git.sh
USER tester
WORKDIR /w
RUN SSH_BIN_DIR=/w/in/ssh OXISH_BIN_DIR=/w/in/oxish GIT_BUILD_DIR=/w/in/git sh test/e2e-git.sh
