.PHONY: build test lint install clean

BIN_EXT := $(if $(filter windows,$(shell go env GOOS)),.exe,)

build:
	go build -o bin/yalie-pp-cli$(BIN_EXT) ./cmd/yalie-pp-cli

test:
	go test ./...

lint:
	golangci-lint run

install:
	go install ./cmd/yalie-pp-cli

clean:
	rm -rf bin/

build-mcp:
	go build -o bin/yalie-pp-mcp$(BIN_EXT) ./cmd/yalie-pp-mcp

install-mcp:
	go install ./cmd/yalie-pp-mcp

build-all: build build-mcp
