BINARY := kms

.PHONY: build test vet clean linux

build:
	go build -trimpath -o bin/$(BINARY) ./cmd/kms

# Static-ish build for the (Linux) KMS server. modernc.org/sqlite is pure Go,
# so CGO stays off and the binary is fully static.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/$(BINARY)-linux-amd64 ./cmd/kms

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
