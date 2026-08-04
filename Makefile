# mpd-proxy is a single Go binary, built from go/ into bin/mpd-proxy and
# installed to $(HOME)/.local/bin/mpd-proxy. It is the small privileged helper
# for mpd-virt: a WireGuard tunnel + split-DNS forwarder that lets this Mac
# reach mpd VMs' 10.163.<NNN>.x bridges. Run it with sudo — it drops root after
# creating the utun. See the README.
GO_DIR := $(CURDIR)/go

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
BIN    := $(BINDIR)/mpd-proxy

# Build with the locally installed Go and nothing else. Go's default
# GOTOOLCHAIN=auto silently downloads a whole toolchain over the network when a
# go.mod names a newer version than the installed one; `local` turns that into
# an immediate, legible build failure instead.
export GOTOOLCHAIN = local

.PHONY: build install uninstall clean test vet fmt fmt-check tidy

build:
	@mkdir -p bin
	cd $(GO_DIR) && go build -o $(CURDIR)/bin/mpd-proxy ./cmd/mpd-proxy
	@echo "Native binary: bin/mpd-proxy"

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
	rm -rf bin
	cd $(GO_DIR) && go clean -cache -testcache
