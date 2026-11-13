UNAME := $(shell uname -sm)
ifeq ($(UNAME),Darwin arm64)
HOST_TARGET := aarch64-apple-darwin
else ifeq ($(UNAME),Linux x86_64)
HOST_TARGET := x86_64-unknown-linux-musl
else ifeq ($(UNAME),Linux aarch64)
HOST_TARGET := aarch64-unknown-linux-musl
else ifeq ($(UNAME),Linux arm64)
HOST_TARGET := aarch64-unknown-linux-musl
endif

TARGET ?= $(HOST_TARGET)
PRODUCT ?= ssh oxish
OUT_DIR ?= dist/release

SUPPORTED_TARGETS := aarch64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl
DOCKER_PLATFORM_x86_64-unknown-linux-musl := linux/amd64
DOCKER_PLATFORM_aarch64-unknown-linux-musl := linux/arm64
DOCKER_PLATFORM := $(DOCKER_PLATFORM_$(TARGET))

OPENSSH_VERSION := $(shell jaq -r '.inputs[] | select(.name == "openssh") | .version' sources.lock.json)
OPENSSH_SHA256 := $(shell jaq -r '.inputs[] | select(.name == "openssh") | .sha256' sources.lock.json)

export TARGET

.PHONY: fetch build binaries binaries-ssh binaries-oxish package verify lint clean check-target

check-target:
	@set -eu; \
		case " $(SUPPORTED_TARGETS) " in \
			*" $(TARGET) "*) ;; \
			*) echo "TARGET must be one of: $(SUPPORTED_TARGETS)" >&2; exit 1 ;; \
		esac; \
		for product in $(PRODUCT); do \
			case $$product in ssh|oxish) ;; *) echo "PRODUCT must be ssh, oxish, or both" >&2; exit 1 ;; esac; \
		done

fetch:
	@sh scripts/fetch-sources.sh

build: binaries package

binaries: check-target $(addprefix binaries-,$(PRODUCT))

binaries-ssh:
	@set -eu; \
		test -n "$(OPENSSH_VERSION)"; \
		dist=dist/ssh/$(TARGET)/bin; \
		case "$(TARGET)" in \
		*-apple-darwin) \
			test "$$(uname -s)" = Darwin; \
			sh scripts/build-macos.sh; \
			test "$$($$dist/ssh -V 2>&1)" = "OpenSSH_$(OPENSSH_VERSION), without OpenSSL" ;; \
		*) \
			mkdir -p "$$dist"; \
			docker buildx build \
				--platform=$(DOCKER_PLATFORM) \
				--progress=plain \
				--build-arg=OPENSSH_VERSION=$(OPENSSH_VERSION) \
				--build-arg=OPENSSH_SHA256=$(OPENSSH_SHA256) \
				--target=artifacts \
				--output=type=local,dest=$$dist \
				.; \
			test -x "$$dist/ssh"; \
			sh scripts/build-record.sh write ssh "$$dist" $(TARGET) ;; \
		esac; \
		echo "wrote $$dist (ssh ssh-keygen ssh-agent ssh-add sftp scp)"

binaries-oxish:
	@set -eu; \
		dist=dist/oxish/$(TARGET)/bin; \
		case "$(TARGET)" in \
		*-apple-darwin) sh scripts/build-oxish-macos.sh ;; \
		*) \
			rm -rf "$$dist"; \
			mkdir -p "$$dist"; \
			docker buildx build \
				--platform=$(DOCKER_PLATFORM) \
				--progress=plain \
				--file=Dockerfile.oxish \
				--target=artifacts \
				--output=type=local,dest=$$dist \
				.; \
			test -x "$$dist/oxish-server"; \
			test -x "$$dist/oxish-keygen"; \
			sh scripts/build-record.sh write oxish "$$dist" $(TARGET) ;; \
		esac; \
		echo "wrote $$dist"

package: check-target
	@set -eu; \
		for product in $(PRODUCT); do \
			case $$product in \
				ssh) sh scripts/package.sh "$(OUT_DIR)" ;; \
				oxish) sh scripts/package-oxish.sh "$(OUT_DIR)" ;; \
			esac; \
		done

verify: check-target
	@sh scripts/verify-release.sh "$(OUT_DIR)"

lint:
	@set -eu; \
		for script in scripts/*.sh test/*.sh; do sh -n "$$script"; done; \
		sh scripts/check-crypto-graph.sh --selftest; \
		sh scripts/audit-release.sh

clean:
	rm -rf dist out stage zipcheck src .work
	find . -path './.git' -prune -o -path './.work' -prune -o -name target -type d -prune -exec rm -rf {} +
