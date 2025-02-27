.PHONY: build test

build:
	go build shards.go

test:
	go test ./...
