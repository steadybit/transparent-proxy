BINARY := transparent-proxy
PKG := github.com/steadybit/transparent-proxy

.PHONY: all build test vet tidy run lint linux clean

all: vet test build

build:
	CGO_ENABLED=0 go build -trimpath -o $(BINARY) .

# Cross-compile for the deployment target to ensure the linux-only
# SO_ORIGINAL_DST path compiles.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/$(BINARY)-linux-arm64 .

test:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

run: build
	./$(BINARY) --config examples/faults.json --log-level debug

clean:
	rm -f $(BINARY)
	rm -rf dist
