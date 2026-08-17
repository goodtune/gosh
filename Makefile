# Strip a leading "v" from the tag so the injected main.version matches what
# GoReleaser produces ({{.Version}} is always v-stripped). Tags are v-prefixed
# (v0.1.0) for Go-module consumption; the binary version string is not, so
# local and release builds agree.
VERSION := $(or $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//'),dev)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/gosh ./cmd/gosh

.PHONY: test
test:
	go test -race ./...

# Integration tests run gosh against a genuine sshd + mosh-server container
# via testcontainers; they need a Docker daemon and are opt-in behind the
# build tag so `make test` stays fast and dependency-free.
.PHONY: integration-test
integration-test:
	go test -race -tags integration -timeout 15m ./test/integration/

.PHONY: build-all
build-all:
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/gosh-linux-amd64 ./cmd/gosh
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/gosh-linux-arm64 ./cmd/gosh
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/gosh-darwin-amd64 ./cmd/gosh
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/gosh-darwin-arm64 ./cmd/gosh
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/gosh-windows-amd64.exe ./cmd/gosh
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/gosh-windows-arm64.exe ./cmd/gosh

.PHONY: clean
clean:
	rm -rf bin dist
