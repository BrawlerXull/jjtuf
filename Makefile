.PHONY: build install test lint clean proto

BINARY_NAME := jjtuf
GO := go

build:
	$(GO) build -o $(BINARY_NAME) .

install:
	$(GO) install .

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY_NAME)
	$(GO) clean

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		internal/jjinterface/proto/simple_op_store.proto

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...
