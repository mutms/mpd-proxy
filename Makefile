# mpd-proxy is a single Go binary, built from go/ into bin/mpd-proxy and
# installed to $(HOME)/.local/bin/mpd-proxy. It is the small privileged helper
# for mpd-virt: a WireGuard tunnel + split-DNS forwarder that lets this Mac
# reach mpd VMs' 10.163.<NNN>.x bridges. Run it with sudo — it drops root after
# creating the utun. See the README.
GO_DIR := $(CURDIR)/go

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
BIN    := $(BINDIR)/mpd-proxy

# Stamped into `mpd-proxy version`; "dev" outside a git checkout, the
# commit hash before any tag exists, "-dirty" appended for uncommitted
# changes. Release builds are made AFTER tagging so the tag lands here.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

# Build with the locally installed Go and nothing else. Go's default
# GOTOOLCHAIN=auto silently downloads a whole toolchain over the network when a
# go.mod names a newer version than the installed one; `local` turns that into
# an immediate, legible build failure instead.
export GOTOOLCHAIN = local

.PHONY: build install uninstall build-static clean test vet fmt fmt-check tidy

build:
	@mkdir -p bin
	cd $(GO_DIR) && go build -ldflags "$(LDFLAGS)" -o $(CURDIR)/bin/mpd-proxy ./cmd/mpd-proxy
	@echo "Native binary: bin/mpd-proxy"

# Self-contained binaries for GitHub releases (Apple Silicon Macs). The
# version is part of the file name, so dist/ is cleared first — otherwise
# binaries of older versions would pile up next to the new ones, waiting
# to be uploaded by mistake.
build-static:
	rm -rf $(CURDIR)/dist
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(CURDIR)/dist/mpd-proxy-$(VERSION)-darwin-arm64 ./cmd/mpd-proxy

install: build
	@mkdir -p "$(BINDIR)"
	@install "$(CURDIR)/bin/mpd-proxy" "$(BIN)"
	@echo "Installed: $(BIN)  (run: sudo $(BIN) up)"

uninstall:
	@rm -f "$(BIN)"
	@echo "Removed: $(BIN)"

test:
	cd $(GO_DIR) && go test ./...

vet:
	cd $(GO_DIR) && go vet ./...

# Apply canonical Go formatting.
fmt:
	cd $(GO_DIR) && gofmt -w .

# Fail if anything is not gofmt-clean.
fmt-check:
	@out=$$(cd $(GO_DIR) && gofmt -l .); \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi
	@echo "gofmt clean"

tidy:
	cd $(GO_DIR) && go mod tidy

clean:
	rm -rf bin dist
	cd $(GO_DIR) && go clean -cache -testcache
