# chromecdm — build and release helpers
#
# Versioning is Semantic Versioning 2.0.0 (https://semver.org).
#
#   - The semantic version is X.Y.Z with no leading zeroes. It is NOT
#     prefixed: the correct semantic version is "1.0.0", not "v1.0.0".
#   - Git tags are prefixed with "v" by convention (v1.0.0); the prefix is
#     part of the tag name, not of the version.
#   - Pre-release: 1.0.0-alpha, 1.0.0-rc.1  (lower precedence than 1.0.0)
#   - Build metadata: 1.0.0+build.5          (ignored for precedence)
#
# The version compiled into the binary is always the bare semver string,
# taken from the git tag with the leading "v" stripped.
#
#   make build          native build into bin/
#   make test           vet + tests
#   make release        cross-compile every target into dist/
#   make snapshot       release with a prerelease version
#   make tag VERSION=1.2.0
#   make clean

BINARY      := wv
SERVER      := chromecdm
MODULE      := chromecdm
VERSION_PKG := $(MODULE)/internal/version

# Bare semantic version (no leading "v"), derived from the git tag.
# `git describe --tags --exact-match` returns e.g. "v1.2.3" when HEAD is
# exactly on a tag; strip the prefix. Otherwise fall back to a snapshot
# version that is still valid semver.
GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null)
ifeq ($(GIT_TAG),)
  VERSION ?= 0.0.0-dev.$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
else
  VERSION ?= $(patsubst v%,%,$(GIT_TAG))
endif

COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X $(VERSION_PKG).Version=$(VERSION) \
  -X $(VERSION_PKG).Commit=$(COMMIT) \
  -X $(VERSION_PKG).Date=$(DATE)

GOFLAGS := -trimpath

# Targets that get release binaries. arm gets GOARM=7 for the common
# Raspberry Pi / ARMv7 case.
PLATFORMS := \
  linux/amd64 \
  linux/arm64 \
  linux/arm \
  linux/386 \
  darwin/amd64 \
  darwin/arm64 \
  windows/amd64 \
  windows/arm64 \
  freebsd/amd64

# SemVer 2.0.0 grammar, tag form (leading "v" allowed). Mirrors the regex
# published at https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
SEMVER_RE := ^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$$

.PHONY: all build test vet fmt release snapshot tag check-version clean version help

all: test build

## build: compile both binaries for the host platform into bin/
build:
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/wv
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(SERVER) ./cmd/chromecdm
	@echo "built bin/$(BINARY) and bin/$(SERVER) [$(VERSION)]"

## test: run vet and the test suite
test:
	go vet ./...
	go test ./... -count=1

## fmt: format all Go sources
fmt:
	gofmt -w cmd internal

## check-version: fail unless VERSION is valid semver
check-version:
	@echo "$(VERSION)" | grep -Eq '$(SEMVER_RE)' \
	  || { echo "error: '$(VERSION)' is not valid semver (expected X.Y.Z[-pre][+build], no leading zeroes)"; exit 1; }
	@echo "semver ok: $(VERSION)"

## release: cross-compile every platform into dist/ with checksums
release: check-version
	@rm -rf dist && mkdir -p dist
	@set -e; for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  goarm=""; [ "$$arch" = "arm" ] && goarm=7; \
	  for cmd in $(BINARY) $(SERVER); do \
	    out=dist/$${cmd}_$(VERSION)_$${os}_$${arch}; \
	    [ "$$os" = "windows" ] && out=$$out.exe; \
	    echo "  $$os/$$arch$${goarm:+ (GOARM=$$goarm)} -> $$out"; \
	    GOOS=$$os GOARCH=$$arch GOARM=$$goarm CGO_ENABLED=0 \
	      go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$out ./cmd/$$cmd; \
	  done; \
	done
	@cd dist && sha256sum * > checksums.txt && echo "  checksums.txt written"

## snapshot: prerelease build with the current commit
snapshot:
	$(MAKE) release VERSION=$(shell git describe --tags --always 2>/dev/null | sed 's/^v//')

## tag: create and push an annotated semver tag (VERSION=X.Y.Z)
tag: check-version
	git tag -a "v$(VERSION)" -m "Release $(VERSION)"
	git push origin "v$(VERSION)"

## version: print the version this tree would build
version:
	@echo "version: $(VERSION)   (semver, no v prefix)"
	@echo "tag:     v$(VERSION)"
	@echo "commit:  $(COMMIT)"
	@echo "date:    $(DATE)"

## clean: remove build output
clean:
	rm -rf bin dist

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
