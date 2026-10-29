# ==============================================================================
# dfir-triage-go Production Build & Cross-Compilation Makefile
# Zero Dependencies / Static Binaries (CGO_ENABLED=0)
# ==============================================================================

BINARY_NAME := dfir-triage
CMD_PATH    := ./cmd/triage
BUILD_DIR   := ./bin
VERSION     := 1.0.0
LDFLAGS     := -s -w

.PHONY: all build-linux build-windows test vet clean checksums

all: build-linux build-windows checksums

build-linux:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_PATH)

build-windows:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)

test:
	CGO_ENABLED=0 go test -v -race ./pkg/...

vet:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go vet ./...
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./...

checksums:
	@cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)* > SHA256SUMS.txt

clean:
	rm -rf $(BUILD_DIR) triage_*.json
