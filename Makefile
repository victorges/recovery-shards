.PHONY: build test release clean

# Get version from GitHub ref, git tag, or use "dev"
VERSION ?= $(shell bash -c '\
	if [ -n "$$GITHUB_REF" ]; then \
		echo "$$GITHUB_REF" | sed "s|refs/tags/||"; \
	else \
		git describe --tags 2>/dev/null || echo "dev"; \
	fi')
OUTPUT := shards

build:
	go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT) .

test:
	go test ./... -v

clean:
	rm -f shards shards-*
