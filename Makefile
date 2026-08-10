VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build test test-corpus verify lint cover clean release-check

all: lint test build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/taggity ./cmd/taggity

# The race detector needs cgo and a C toolchain, which a pure-Go project has no
# other reason to require. Skip it when one is unavailable rather than failing
# the whole target; CI runs the race build on every platform.
RACE := $(shell go env CGO_ENABLED | grep -q 1 && command -v gcc >/dev/null 2>&1 && echo -race)

test:
	go test $(RACE) ./...

# Tests tagged "corpus" clone real repositories and check the engine against
# graded advisories. Excluded from the default target so the normal suite stays
# hermetic.
#
# -count=1 defeats the test cache deliberately: a cached pass is not evidence
# that the corpus still reproduces, and this target exists to produce evidence.
test-corpus:
	go test $(RACE) -tags corpus -count=1 ./...

# Everything the README claims, verified. Not in `all` because it needs network.
verify: lint test test-corpus

lint:
	golangci-lint run

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

clean:
	rm -rf bin coverage.out
