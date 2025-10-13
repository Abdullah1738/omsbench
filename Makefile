BINARY := bin/omsbench

.PHONY: build build-arm64 test

build:
	mkdir -p bin
	go build -o $(BINARY) ./cmd/omsbench

build-arm64:
	mkdir -p bin
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(BINARY)-linux-arm64 ./cmd/omsbench

test:
	go test ./...
