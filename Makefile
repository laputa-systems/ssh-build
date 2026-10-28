OPENSSH_VERSION ?= $(shell sed -n 's/^OPENSSH_VERSION=//p' scripts/fetch-sources.sh)
DOCKER_PLATFORM ?= linux/arm64

MACOS_DIST ?= dist/macos/bin
LINUX_ARCH = $(if $(findstring arm64,$(DOCKER_PLATFORM)),aarch64,x86_64)
LINUX_DIST ?= dist/linux-$(LINUX_ARCH)/bin

.PHONY: macos linux

macos:
	@set -eu; \
		test -n "$(OPENSSH_VERSION)"; \
		test "$$(uname -s)" = Darwin; \
		sh scripts/build-macos.sh; \
		test "$$($(MACOS_DIST)/ssh -V 2>&1)" = "OpenSSH_$(OPENSSH_VERSION), without OpenSSL"; \
		echo "wrote $(MACOS_DIST) (ssh ssh-keygen ssh-agent ssh-add sftp scp)"

linux:
	@set -eu; \
		test -n "$(OPENSSH_VERSION)"; \
		mkdir -p "$(LINUX_DIST)"; \
		docker buildx build \
			--platform=$(DOCKER_PLATFORM) \
			--progress=plain \
			--build-arg=OPENSSH_VERSION=$(OPENSSH_VERSION) \
			--build-arg=OPENSSH_SHA256=$$(sed -n 's/^OPENSSH_SHA256=//p' scripts/fetch-sources.sh) \
			--target=artifacts \
			--output=type=local,dest=$(LINUX_DIST) \
			.; \
		test -x "$(LINUX_DIST)/ssh"; \
		echo "wrote $(LINUX_DIST)"
